package middleware

import (
	"net/http"
)

// ErrorHandler is called when validation fails.
type ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

// Options configures middleware behavior.
type Options struct {
	Security         *SecurityRegistry
	ValidateRequest  bool
	ValidateResponse bool
	ErrorHandler     ErrorHandler
}

// DefaultOptions returns options with sensible defaults.
func DefaultOptions() *Options {
	return &Options{
		Security:        NewSecurityRegistry(),
		ValidateRequest: true,
	}
}
