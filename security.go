package middleware

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"strings"
)

// SecurityHandler validates credentials for a specific security scheme.
type SecurityHandler interface {
	Handle(r *http.Request, scopes []string) (*SecurityContext, error)
}

// BearerHandler validates HTTP Bearer authentication.
type BearerHandler func(ctx context.Context, token string) (*BearerAuth, error)

// Handle implements SecurityHandler.
func (h BearerHandler) Handle(r *http.Request, _ []string) (*SecurityContext, error) {
	token := ExtractBearerToken(r)
	if token == "" {
		return nil, NewUnauthorizedError("bearer", "missing bearer token")
	}
	auth, err := h(r.Context(), token)
	if err != nil {
		return nil, err
	}
	return &SecurityContext{Bearer: auth}, nil
}

// BasicHandler validates HTTP Basic authentication.
type BasicHandler func(ctx context.Context, username, password string) (*BasicAuth, error)

// Handle implements SecurityHandler.
func (h BasicHandler) Handle(r *http.Request, _ []string) (*SecurityContext, error) {
	username, password, ok := ExtractBasicAuth(r)
	if !ok {
		return nil, NewUnauthorizedError("basic", "missing basic auth credentials")
	}
	auth, err := h(r.Context(), username, password)
	if err != nil {
		return nil, err
	}
	return &SecurityContext{Basic: auth}, nil
}

// APIKeyHandler validates API key authentication.
type APIKeyHandler func(ctx context.Context, key string) (*APIKeyAuth, error)

// APIKeyConfig wraps an APIKeyHandler with location info.
type APIKeyConfig struct {
	Handler  APIKeyHandler
	Location string
	Name     string
}

// Handle implements SecurityHandler.
func (c APIKeyConfig) Handle(r *http.Request, _ []string) (*SecurityContext, error) {
	key := ExtractAPIKey(r, c.Location, c.Name)
	if key == "" {
		return nil, NewUnauthorizedError("apiKey", "missing API key")
	}
	auth, err := c.Handler(r.Context(), key)
	if err != nil {
		return nil, err
	}
	// Ensure location info is set
	auth.Location = c.Location
	auth.Name = c.Name
	return &SecurityContext{APIKey: auth}, nil
}

// OAuth2Handler validates OAuth2 tokens and scopes.
type OAuth2Handler func(ctx context.Context, token string, scopes []string) (*OAuth2Auth, error)

// Handle implements SecurityHandler.
func (h OAuth2Handler) Handle(r *http.Request, scopes []string) (*SecurityContext, error) {
	token := ExtractBearerToken(r)
	if token == "" {
		return nil, NewUnauthorizedError("oauth2", "missing access token")
	}
	auth, err := h(r.Context(), token, scopes)
	if err != nil {
		return nil, err
	}
	return &SecurityContext{OAuth2: auth}, nil
}

// OpenIDConnectHandler validates OpenID Connect tokens.
type OpenIDConnectHandler func(ctx context.Context, token string, scopes []string) (*OpenIDConnectAuth, error)

// Handle implements SecurityHandler.
func (h OpenIDConnectHandler) Handle(r *http.Request, scopes []string) (*SecurityContext, error) {
	token := ExtractBearerToken(r)
	if token == "" {
		return nil, NewUnauthorizedError("openIdConnect", "missing token")
	}
	auth, err := h(r.Context(), token, scopes)
	if err != nil {
		return nil, err
	}
	return &SecurityContext{OpenIDConnect: auth}, nil
}

// MutualTLSHandler validates client certificates.
type MutualTLSHandler func(ctx context.Context, cert *x509.Certificate) (*MutualTLSAuth, error)

// Handle implements SecurityHandler.
func (h MutualTLSHandler) Handle(r *http.Request, _ []string) (*SecurityContext, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, NewUnauthorizedError("mutualTLS", "missing client certificate")
	}
	cert := r.TLS.PeerCertificates[0]
	auth, err := h(r.Context(), cert)
	if err != nil {
		return nil, err
	}
	return &SecurityContext{MutualTLS: auth}, nil
}

// SecurityRegistry holds handlers for named security schemes.
type SecurityRegistry struct {
	handlers map[string]SecurityHandler
}

// NewSecurityRegistry creates a new security registry.
func NewSecurityRegistry() *SecurityRegistry {
	return &SecurityRegistry{handlers: make(map[string]SecurityHandler)}
}

// Register adds a handler for a named security scheme.
func (r *SecurityRegistry) Register(name string, handler SecurityHandler) {
	r.handlers[name] = handler
}

// RegisterBearer registers a bearer token handler.
func (r *SecurityRegistry) RegisterBearer(name string, handler BearerHandler) {
	r.handlers[name] = handler
}

// RegisterBasic registers a basic auth handler.
func (r *SecurityRegistry) RegisterBasic(name string, handler BasicHandler) {
	r.handlers[name] = handler
}

// RegisterAPIKey registers an API key handler.
func (r *SecurityRegistry) RegisterAPIKey(name string, handler APIKeyHandler, location, paramName string) {
	r.handlers[name] = APIKeyConfig{Handler: handler, Location: location, Name: paramName}
}

// RegisterOAuth2 registers an OAuth2 handler.
func (r *SecurityRegistry) RegisterOAuth2(name string, handler OAuth2Handler) {
	r.handlers[name] = handler
}

// RegisterOpenIDConnect registers an OpenID Connect handler.
func (r *SecurityRegistry) RegisterOpenIDConnect(name string, handler OpenIDConnectHandler) {
	r.handlers[name] = handler
}

// RegisterMutualTLS registers a mutual TLS handler.
func (r *SecurityRegistry) RegisterMutualTLS(name string, handler MutualTLSHandler) {
	r.handlers[name] = handler
}

// Get returns the handler for a scheme, or nil if not registered.
func (r *SecurityRegistry) Get(name string) SecurityHandler {
	return r.handlers[name]
}

// ExtractBearerToken extracts the bearer token from the Authorization header.
func ExtractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && strings.EqualFold(auth[:7], "Bearer ") {
		return auth[7:]
	}
	return ""
}

// ExtractBasicAuth extracts username and password from Basic auth header.
func ExtractBasicAuth(r *http.Request) (username, password string, ok bool) {
	auth := r.Header.Get("Authorization")
	if len(auth) > 6 && strings.EqualFold(auth[:6], "Basic ") {
		payload, err := base64.StdEncoding.DecodeString(auth[6:])
		if err != nil {
			return "", "", false
		}
		parts := strings.SplitN(string(payload), ":", 2)
		if len(parts) != 2 {
			return "", "", false
		}
		return parts[0], parts[1], true
	}
	return "", "", false
}

// ExtractAPIKey extracts an API key from the specified location.
func ExtractAPIKey(r *http.Request, location, name string) string {
	switch location {
	case "header":
		return r.Header.Get(name)
	case "query":
		return r.URL.Query().Get(name)
	case "cookie":
		if c, err := r.Cookie(name); err == nil {
			return c.Value
		}
	}
	return ""
}

// MergeSecurityContext merges src into dst, populating non-nil fields.
func MergeSecurityContext(dst, src *SecurityContext) {
	if src.Bearer != nil {
		dst.Bearer = src.Bearer
	}
	if src.Basic != nil {
		dst.Basic = src.Basic
	}
	if src.APIKey != nil {
		dst.APIKey = src.APIKey
	}
	if src.OAuth2 != nil {
		dst.OAuth2 = src.OAuth2
	}
	if src.OpenIDConnect != nil {
		dst.OpenIDConnect = src.OpenIDConnect
	}
	if src.MutualTLS != nil {
		dst.MutualTLS = src.MutualTLS
	}
}
