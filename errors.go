package middleware

import (
	"net/http"

	"github.com/pb33f/libopenapi-validator/errors"
)

// ValidationError wraps libopenapi-validator errors with HTTP semantics.
type ValidationError struct {
	StatusCode int
	Message    string
	Errors     []*errors.ValidationError
}

func (e *ValidationError) Error() string {
	return e.Message
}

// AuthError represents authentication/authorization failures.
type AuthError struct {
	StatusCode int
	Scheme     string
	Message    string
	Scopes     []string
}

func (e *AuthError) Error() string {
	return e.Message
}

// IsUnauthorized returns true if error is 401 (missing/invalid credentials).
func (e *AuthError) IsUnauthorized() bool {
	return e.StatusCode == http.StatusUnauthorized
}

// IsForbidden returns true if error is 403 (valid credentials, insufficient permissions).
func (e *AuthError) IsForbidden() bool {
	return e.StatusCode == http.StatusForbidden
}

// NewUnauthorizedError creates a 401 error.
func NewUnauthorizedError(scheme, message string) *AuthError {
	return &AuthError{
		StatusCode: http.StatusUnauthorized,
		Scheme:     scheme,
		Message:    message,
	}
}

// NewForbiddenError creates a 403 error.
func NewForbiddenError(scheme, message string, scopes []string) *AuthError {
	return &AuthError{
		StatusCode: http.StatusForbidden,
		Scheme:     scheme,
		Message:    message,
		Scopes:     scopes,
	}
}
