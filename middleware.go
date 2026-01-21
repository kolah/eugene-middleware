package middleware

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"slices"

	"github.com/pb33f/libopenapi"
	validator "github.com/pb33f/libopenapi-validator"
	validatorErrors "github.com/pb33f/libopenapi-validator/errors"
	v3 "github.com/pb33f/libopenapi/datamodel/high/v3"
)

// Middleware validates requests against an OpenAPI spec.
type Middleware struct {
	validator validator.Validator
	doc       libopenapi.Document
	model     *libopenapi.DocumentModel[v3.Document]
	options   *Options
}

// New creates middleware from an OpenAPI spec string.
func New(spec string, opts *Options) (*Middleware, error) {
	return NewFromBytes([]byte(spec), opts)
}

// NewFromBytes creates middleware from OpenAPI spec bytes.
func NewFromBytes(spec []byte, opts *Options) (*Middleware, error) {
	doc, err := libopenapi.NewDocument(spec)
	if err != nil {
		return nil, err
	}

	v, errs := validator.NewValidator(doc)
	if len(errs) > 0 {
		return nil, errs[0]
	}

	model, err := doc.BuildV3Model()
	if err != nil {
		return nil, err
	}

	if opts == nil {
		opts = DefaultOptions()
	}

	return &Middleware{
		validator: v,
		doc:       doc,
		model:     model,
		options:   opts,
	}, nil
}

// NewFromBase64 creates middleware from base64-encoded spec.
func NewFromBase64(encoded string, opts *Options) (*Middleware, error) {
	spec, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	return NewFromBytes(spec, opts)
}

// Handler returns an http.Handler middleware.
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := m.validateHost(r); err != nil {
			m.handleHostError(w, r, err)
			return
		}

		op := m.findOperation(r.URL.Path, r.Method)
		if op == nil && m.options.StrictRoutes {
			m.handleRouteError(w, r, NewRouteNotFoundError(r.URL.Path, r.Method))
			return
		}

		if m.options.ValidateRequest {
			valid, errors := m.validator.ValidateHttpRequestSync(r)
			if !valid {
				m.handleValidationError(w, r, errors)
				return
			}
		}

		if err := m.validateSecurityWithOp(w, r, op); err != nil {
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (m *Middleware) validateSecurityWithOp(w http.ResponseWriter, r *http.Request, op *v3.Operation) error {
	if m.model == nil || m.model.Model.Paths == nil {
		return nil
	}

	if op == nil {
		return nil
	}

	secReqs := op.Security
	if secReqs == nil {
		secReqs = m.model.Model.Security
	}

	if len(secReqs) == 0 {
		return nil
	}

	var lastErr error

	// Each item in secReqs is an OR alternative
	for _, req := range secReqs {
		// Empty requirement means no auth needed
		if req.Requirements == nil || req.Requirements.Len() == 0 {
			return nil
		}

		// All schemes in one requirement are AND (all must pass)
		secCtx := &SecurityContext{}
		allPassed := true

		for pair := req.Requirements.Oldest(); pair != nil; pair = pair.Next() {
			schemeName := pair.Key
			scopes := pair.Value

			handler := m.options.Security.Get(schemeName)
			if handler == nil {
				lastErr = NewUnauthorizedError(schemeName, "security scheme not configured")
				allPassed = false
				break
			}

			result, err := handler.Handle(r, scopes)
			if err != nil {
				lastErr = err
				allPassed = false
				break
			}

			// Merge this handler's result into the combined context
			MergeSecurityContext(secCtx, result)
		}

		// If all schemes in this requirement passed, we're done (OR satisfied)
		if allPassed {
			ctx := WithSecurityContext(r.Context(), secCtx)
			*r = *r.WithContext(ctx)
			return nil
		}
	}

	// No OR alternative succeeded
	if lastErr != nil {
		m.handleAuthError(w, r, lastErr)
	}
	return lastErr
}

func (m *Middleware) findOperation(path, method string) *v3.Operation {
	if m.model.Model.Paths == nil || m.model.Model.Paths.PathItems == nil {
		return nil
	}

	if m.options.BasePath != "" {
		path = strings.TrimPrefix(path, m.options.BasePath)
		if path == "" {
			path = "/"
		}
	}

	for pair := m.model.Model.Paths.PathItems.Oldest(); pair != nil; pair = pair.Next() {
		pathPattern := pair.Key
		pathItem := pair.Value

		if matchPath(pathPattern, path) {
			return getOperation(pathItem, method)
		}
	}
	return nil
}

func matchPath(pattern, path string) bool {
	patternParts := splitPath(pattern)
	pathParts := splitPath(path)

	if len(patternParts) != len(pathParts) {
		return false
	}

	for i, pp := range patternParts {
		if len(pp) > 0 && pp[0] == '{' && pp[len(pp)-1] == '}' {
			continue
		}
		if pp != pathParts[i] {
			return false
		}
	}
	return true
}

func splitPath(p string) []string {
	if len(p) > 0 && p[0] == '/' {
		p = p[1:]
	}
	if len(p) == 0 {
		return nil
	}
	var parts []string
	start := 0
	for i := range len(p) {
		if p[i] == '/' {
			parts = append(parts, p[start:i])
			start = i + 1
		}
	}
	parts = append(parts, p[start:])
	return parts
}

func getOperation(pathItem *v3.PathItem, method string) *v3.Operation {
	switch method {
	case http.MethodGet:
		return pathItem.Get
	case http.MethodPost:
		return pathItem.Post
	case http.MethodPut:
		return pathItem.Put
	case http.MethodDelete:
		return pathItem.Delete
	case http.MethodPatch:
		return pathItem.Patch
	case http.MethodHead:
		return pathItem.Head
	case http.MethodOptions:
		return pathItem.Options
	case http.MethodTrace:
		return pathItem.Trace
	}
	return nil
}

func (m *Middleware) handleValidationError(w http.ResponseWriter, r *http.Request, errors []*validatorErrors.ValidationError) {
	err := &ValidationError{
		StatusCode: http.StatusBadRequest,
		Message:    "request validation failed",
		Errors:     errors,
	}

	if m.options.ErrorHandler != nil {
		m.options.ErrorHandler(w, r, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]any{
		"error":   "validation_error",
		"message": err.Message,
		"details": formatValidationErrors(errors),
	})
}

func (m *Middleware) handleAuthError(w http.ResponseWriter, r *http.Request, err error) {
	authErr, ok := err.(*AuthError)
	if !ok {
		authErr = NewUnauthorizedError("", err.Error())
	}

	if m.options.ErrorHandler != nil {
		m.options.ErrorHandler(w, r, authErr)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(authErr.StatusCode)

	response := map[string]any{
		"error":   "authentication_error",
		"message": authErr.Message,
	}
	if len(authErr.Scopes) > 0 {
		response["required_scopes"] = authErr.Scopes
	}
	json.NewEncoder(w).Encode(response)
}

func (m *Middleware) validateHost(r *http.Request) error {
	var allowedHosts []string

	if len(m.options.AllowedHosts) > 0 {
		allowedHosts = m.options.AllowedHosts
	} else if m.options.UseSchemaServersAsHosts {
		allowedHosts = m.extractHostsFromServers()
	}

	if len(allowedHosts) == 0 {
		return nil
	}

	host := r.Host
	if slices.Contains(allowedHosts, host) {
		return nil
	}

	return NewHostError(host, "host not allowed")
}

func (m *Middleware) extractHostsFromServers() []string {
	if m.model == nil || m.model.Model.Servers == nil {
		return nil
	}

	var hosts []string
	for _, server := range m.model.Model.Servers {
		if server.URL == "" {
			continue
		}
		parsed, err := url.Parse(server.URL)
		if err != nil {
			continue
		}
		if parsed.Host != "" {
			hosts = append(hosts, parsed.Host)
		}
	}
	return hosts
}

func (m *Middleware) handleHostError(w http.ResponseWriter, r *http.Request, err error) {
	var hostErr *HostError
	ok := errors.As(err, &hostErr)
	if !ok {
		hostErr = NewHostError(r.Host, err.Error())
	}

	if m.options.ErrorHandler != nil {
		m.options.ErrorHandler(w, r, hostErr)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(hostErr.StatusCode)
	json.NewEncoder(w).Encode(map[string]any{
		"error":   "host_not_allowed",
		"message": hostErr.Message,
	})
}

func (m *Middleware) handleRouteError(w http.ResponseWriter, r *http.Request, err error) {
	var routeErr *RouteError
	ok := errors.As(err, &routeErr)
	if !ok {
		routeErr = NewRouteNotFoundError(r.URL.Path, r.Method)
	}

	if m.options.ErrorHandler != nil {
		m.options.ErrorHandler(w, r, routeErr)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(routeErr.StatusCode)
	json.NewEncoder(w).Encode(map[string]any{
		"error":   "route_not_found",
		"message": routeErr.Message,
	})
}

func formatValidationErrors(errors []*validatorErrors.ValidationError) []map[string]any {
	var result []map[string]any
	for _, e := range errors {
		item := map[string]any{
			"message": e.Message,
		}
		if e.Reason != "" {
			item["reason"] = e.Reason
		}
		if e.HowToFix != "" {
			item["howToFix"] = e.HowToFix
		}
		result = append(result, item)
	}
	return result
}
