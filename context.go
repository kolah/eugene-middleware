package middleware

import (
	"context"
	"crypto/x509"
)

type contextKey string

const securityContextKey contextKey = "eugene:security"

// SecurityContext holds all validated authentication for a request.
// Multiple fields may be populated when AND security requirements are used.
type SecurityContext struct {
	// HTTP Bearer authentication (type: http, scheme: bearer)
	Bearer *BearerAuth

	// HTTP Basic authentication (type: http, scheme: basic)
	Basic *BasicAuth

	// API key authentication (type: apiKey)
	APIKey *APIKeyAuth

	// OAuth2 authentication (type: oauth2)
	OAuth2 *OAuth2Auth

	// OpenID Connect authentication (type: openIdConnect)
	OpenIDConnect *OpenIDConnectAuth

	// Mutual TLS authentication (type: mutualTLS)
	MutualTLS *MutualTLSAuth
}

// BearerAuth contains validated HTTP bearer token.
type BearerAuth struct {
	Token string
}

// BasicAuth contains validated HTTP basic credentials.
type BasicAuth struct {
	Username string
	Password string
}

// APIKeyAuth contains validated API key.
type APIKeyAuth struct {
	Key      string
	Name     string // Parameter name from spec
	Location string // header, query, cookie
}

// OAuth2Auth contains validated OAuth2 token.
type OAuth2Auth struct {
	Token  string
	Scopes []string
	Flow   string // implicit, password, clientCredentials, authorizationCode, deviceAuthorization
}

// OpenIDConnectAuth contains validated OpenID Connect token.
type OpenIDConnectAuth struct {
	Token  string
	Scopes []string
	Issuer string
}

// MutualTLSAuth contains validated client certificate.
type MutualTLSAuth struct {
	Subject     string
	Issuer      string
	Certificate *x509.Certificate
}

// WithSecurityContext stores security context in the request context.
func WithSecurityContext(ctx context.Context, sec *SecurityContext) context.Context {
	return context.WithValue(ctx, securityContextKey, sec)
}

// GetSecurityContext retrieves security context from the request context.
func GetSecurityContext(ctx context.Context) *SecurityContext {
	if v := ctx.Value(securityContextKey); v != nil {
		return v.(*SecurityContext)
	}
	return nil
}
