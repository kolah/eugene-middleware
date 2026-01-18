package middleware

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/pb33f/libopenapi"
	v3 "github.com/pb33f/libopenapi/datamodel/high/v3"
	validator "github.com/pb33f/libopenapi-validator"
	validatorErrors "github.com/pb33f/libopenapi-validator/errors"
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
		if m.options.ValidateRequest {
			valid, errors := m.validator.ValidateHttpRequestSync(r)
			if !valid {
				m.handleValidationError(w, r, errors)
				return
			}
		}

		if err := m.validateSecurity(w, r); err != nil {
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (m *Middleware) validateSecurity(w http.ResponseWriter, r *http.Request) error {
	if m.model == nil || m.model.Model.Paths == nil {
		return nil
	}

	op := m.findOperation(r.URL.Path, r.Method)
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
	for i := 0; i < len(p); i++ {
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
