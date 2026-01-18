package middleware

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testSpec = `
openapi: "3.2.0"
info:
  title: Test API
  version: "1.0"
paths:
  /pets:
    get:
      operationId: listPets
      security: []
      responses:
        "200":
          description: OK
    post:
      operationId: createPet
      security:
        - bearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - name
              properties:
                name:
                  type: string
      responses:
        "201":
          description: Created
  /pets/{id}:
    get:
      operationId: getPet
      security:
        - apiKey: []
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
      responses:
        "200":
          description: OK
  /admin:
    get:
      operationId: adminEndpoint
      security:
        - oauth2:
            - admin:read
      responses:
        "200":
          description: OK
  /secure:
    get:
      operationId: secureEndpoint
      security:
        - bearerAuth: []
          apiKey: []
      responses:
        "200":
          description: OK
  /flexible:
    get:
      operationId: flexibleEndpoint
      security:
        - bearerAuth: []
        - apiKey: []
      responses:
        "200":
          description: OK
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
    apiKey:
      type: apiKey
      in: header
      name: X-API-Key
    oauth2:
      type: oauth2
      flows:
        authorizationCode:
          authorizationUrl: https://example.com/oauth/authorize
          tokenUrl: https://example.com/oauth/token
          scopes:
            admin:read: Read admin data
`

func TestNew(t *testing.T) {
	mw, err := New(testSpec, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if mw == nil {
		t.Fatal("New() returned nil middleware")
	}
}

func TestNewFromBase64(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte(testSpec))
	mw, err := NewFromBase64(encoded, nil)
	if err != nil {
		t.Fatalf("NewFromBase64() error = %v", err)
	}
	if mw == nil {
		t.Fatal("NewFromBase64() returned nil middleware")
	}
}

func TestSecurityRegistry(t *testing.T) {
	reg := NewSecurityRegistry()

	t.Run("RegisterBearer", func(t *testing.T) {
		reg.RegisterBearer("bearer", func(ctx context.Context, token string) (*BearerAuth, error) {
			return &BearerAuth{Token: token}, nil
		})
		if reg.Get("bearer") == nil {
			t.Error("bearer handler not registered")
		}
	})

	t.Run("RegisterBasic", func(t *testing.T) {
		reg.RegisterBasic("basic", func(ctx context.Context, username, password string) (*BasicAuth, error) {
			return &BasicAuth{Username: username, Password: password}, nil
		})
		if reg.Get("basic") == nil {
			t.Error("basic handler not registered")
		}
	})

	t.Run("RegisterAPIKey", func(t *testing.T) {
		reg.RegisterAPIKey("apiKey", func(ctx context.Context, key string) (*APIKeyAuth, error) {
			return &APIKeyAuth{Key: key}, nil
		}, "header", "X-API-Key")
		if reg.Get("apiKey") == nil {
			t.Error("apiKey handler not registered")
		}
	})

	t.Run("RegisterOAuth2", func(t *testing.T) {
		reg.RegisterOAuth2("oauth2", func(ctx context.Context, token string, scopes []string) (*OAuth2Auth, error) {
			return &OAuth2Auth{Token: token, Scopes: scopes}, nil
		})
		if reg.Get("oauth2") == nil {
			t.Error("oauth2 handler not registered")
		}
	})

	t.Run("RegisterOpenIDConnect", func(t *testing.T) {
		reg.RegisterOpenIDConnect("oidc", func(ctx context.Context, token string, scopes []string) (*OpenIDConnectAuth, error) {
			return &OpenIDConnectAuth{Token: token, Scopes: scopes, Issuer: "https://example.com"}, nil
		})
		if reg.Get("oidc") == nil {
			t.Error("oidc handler not registered")
		}
	})
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected string
	}{
		{"valid bearer", "Bearer token123", "token123"},
		{"lowercase bearer", "bearer token123", "token123"},
		{"no bearer prefix", "token123", ""},
		{"empty header", "", ""},
		{"basic auth", "Basic dXNlcjpwYXNz", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			got := ExtractBearerToken(req)
			if got != tt.expected {
				t.Errorf("ExtractBearerToken() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestExtractBasicAuth(t *testing.T) {
	t.Run("valid basic auth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user:pass")))
		username, password, ok := ExtractBasicAuth(req)
		if !ok {
			t.Error("ExtractBasicAuth() returned false")
		}
		if username != "user" || password != "pass" {
			t.Errorf("ExtractBasicAuth() = %q, %q, want user, pass", username, password)
		}
	})

	t.Run("missing header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		_, _, ok := ExtractBasicAuth(req)
		if ok {
			t.Error("ExtractBasicAuth() should return false for missing header")
		}
	})

	t.Run("invalid base64", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Basic not-base64!")
		_, _, ok := ExtractBasicAuth(req)
		if ok {
			t.Error("ExtractBasicAuth() should return false for invalid base64")
		}
	})
}

func TestExtractAPIKey(t *testing.T) {
	t.Run("from header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-API-Key", "key123")
		got := ExtractAPIKey(req, "header", "X-API-Key")
		if got != "key123" {
			t.Errorf("ExtractAPIKey() = %q, want %q", got, "key123")
		}
	})

	t.Run("from query", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/?api_key=key456", nil)
		got := ExtractAPIKey(req, "query", "api_key")
		if got != "key456" {
			t.Errorf("ExtractAPIKey() = %q, want %q", got, "key456")
		}
	})

	t.Run("from cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "session", Value: "cookie789"})
		got := ExtractAPIKey(req, "cookie", "session")
		if got != "cookie789" {
			t.Errorf("ExtractAPIKey() = %q, want %q", got, "cookie789")
		}
	})
}

func TestMiddleware_NoSecurityEndpoint(t *testing.T) {
	mw, err := New(testSpec, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	handler := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/pets", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestMiddleware_BearerAuth(t *testing.T) {
	opts := DefaultOptions()
	opts.Security.RegisterBearer("bearerAuth", func(ctx context.Context, token string) (*BearerAuth, error) {
		if token == "valid-token" {
			return &BearerAuth{Token: token}, nil
		}
		return nil, NewUnauthorizedError("bearerAuth", "invalid token")
	})

	mw, err := New(testSpec, opts)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	handler := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sec := GetSecurityContext(r.Context())
		if sec == nil || sec.Bearer == nil {
			t.Error("expected BearerAuth in context")
		}
		w.WriteHeader(http.StatusCreated)
	}))

	t.Run("valid token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/pets", strings.NewReader(`{"name":"Fluffy"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer valid-token")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusCreated {
			t.Errorf("expected status 201, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("missing token", func(t *testing.T) {
		opts := DefaultOptions()
		opts.ValidateRequest = false
		opts.Security.RegisterBearer("bearerAuth", func(ctx context.Context, token string) (*BearerAuth, error) {
			if token == "valid-token" {
				return &BearerAuth{Token: token}, nil
			}
			return nil, NewUnauthorizedError("bearerAuth", "invalid token")
		})
		mw, _ := New(testSpec, opts)
		h := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
		}))

		req := httptest.NewRequest(http.MethodPost, "/pets", strings.NewReader(`{"name":"Fluffy"}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/pets", strings.NewReader(`{"name":"Fluffy"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer invalid-token")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d", rec.Code)
		}
	})
}

func TestMiddleware_ANDSecurity(t *testing.T) {
	opts := DefaultOptions()
	opts.ValidateRequest = false
	opts.Security.RegisterBearer("bearerAuth", func(ctx context.Context, token string) (*BearerAuth, error) {
		return &BearerAuth{Token: token}, nil
	})
	opts.Security.RegisterAPIKey("apiKey", func(ctx context.Context, key string) (*APIKeyAuth, error) {
		return &APIKeyAuth{Key: key}, nil
	}, "header", "X-API-Key")

	mw, err := New(testSpec, opts)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	handler := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sec := GetSecurityContext(r.Context())
		if sec == nil {
			t.Error("expected SecurityContext")
			return
		}
		if sec.Bearer == nil {
			t.Error("expected Bearer in context")
		}
		if sec.APIKey == nil {
			t.Error("expected APIKey in context")
		}
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("both auth methods provided", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/secure", nil)
		req.Header.Set("Authorization", "Bearer token123")
		req.Header.Set("X-API-Key", "key456")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("only bearer provided", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/secure", nil)
		req.Header.Set("Authorization", "Bearer token123")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401 (AND requires both), got %d", rec.Code)
		}
	})

	t.Run("only apikey provided", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/secure", nil)
		req.Header.Set("X-API-Key", "key456")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401 (AND requires both), got %d", rec.Code)
		}
	})
}

func TestMiddleware_ORSecurity(t *testing.T) {
	opts := DefaultOptions()
	opts.ValidateRequest = false
	opts.Security.RegisterBearer("bearerAuth", func(ctx context.Context, token string) (*BearerAuth, error) {
		return &BearerAuth{Token: token}, nil
	})
	opts.Security.RegisterAPIKey("apiKey", func(ctx context.Context, key string) (*APIKeyAuth, error) {
		return &APIKeyAuth{Key: key}, nil
	}, "header", "X-API-Key")

	mw, err := New(testSpec, opts)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	t.Run("bearer auth only", func(t *testing.T) {
		handler := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sec := GetSecurityContext(r.Context())
			if sec == nil || sec.Bearer == nil {
				t.Error("expected Bearer in context")
			}
			if sec.APIKey != nil {
				t.Error("expected no APIKey in context (OR should use first match)")
			}
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/flexible", nil)
		req.Header.Set("Authorization", "Bearer token123")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}
	})

	t.Run("apikey auth only", func(t *testing.T) {
		handler := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sec := GetSecurityContext(r.Context())
			if sec == nil || sec.APIKey == nil {
				t.Error("expected APIKey in context")
			}
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/flexible", nil)
		req.Header.Set("X-API-Key", "key456")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}
	})

	t.Run("neither provided", func(t *testing.T) {
		handler := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/flexible", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d", rec.Code)
		}
	})
}

func TestMiddleware_RequestValidation(t *testing.T) {
	opts := DefaultOptions()
	opts.Security.RegisterBearer("bearerAuth", func(ctx context.Context, token string) (*BearerAuth, error) {
		return &BearerAuth{Token: token}, nil
	})

	mw, err := New(testSpec, opts)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	handler := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))

	t.Run("missing required field", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/pets", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer token")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected status 400, got %d: %s", rec.Code, rec.Body.String())
		}
	})
}

func TestAuthError(t *testing.T) {
	t.Run("unauthorized", func(t *testing.T) {
		err := NewUnauthorizedError("bearer", "invalid token")
		if !err.IsUnauthorized() {
			t.Error("expected IsUnauthorized() to be true")
		}
		if err.IsForbidden() {
			t.Error("expected IsForbidden() to be false")
		}
	})

	t.Run("forbidden", func(t *testing.T) {
		err := NewForbiddenError("oauth2", "insufficient scope", []string{"admin:read"})
		if err.IsUnauthorized() {
			t.Error("expected IsUnauthorized() to be false")
		}
		if !err.IsForbidden() {
			t.Error("expected IsForbidden() to be true")
		}
		if len(err.Scopes) != 1 || err.Scopes[0] != "admin:read" {
			t.Errorf("expected scopes [admin:read], got %v", err.Scopes)
		}
	})
}

func TestSecurityContext(t *testing.T) {
	ctx := context.Background()

	t.Run("WithSecurityContext and GetSecurityContext", func(t *testing.T) {
		sec := &SecurityContext{Bearer: &BearerAuth{Token: "token123"}}
		ctx := WithSecurityContext(ctx, sec)
		got := GetSecurityContext(ctx)
		if got == nil {
			t.Fatal("GetSecurityContext() returned nil")
		}
		if got.Bearer == nil || got.Bearer.Token != "token123" {
			t.Errorf("expected Bearer with token 'token123', got %+v", got.Bearer)
		}
	})

	t.Run("GetSecurityContext returns nil for empty context", func(t *testing.T) {
		got := GetSecurityContext(ctx)
		if got != nil {
			t.Error("expected nil for empty context")
		}
	})

	t.Run("multiple auth types", func(t *testing.T) {
		sec := &SecurityContext{
			Bearer: &BearerAuth{Token: "token"},
			APIKey: &APIKeyAuth{Key: "key", Location: "header", Name: "X-API-Key"},
		}
		ctx := WithSecurityContext(ctx, sec)
		got := GetSecurityContext(ctx)
		if got == nil {
			t.Fatal("GetSecurityContext() returned nil")
		}
		if got.Bearer == nil {
			t.Error("expected Bearer to be set")
		}
		if got.APIKey == nil {
			t.Error("expected APIKey to be set")
		}
	})
}

func TestMergeSecurityContext(t *testing.T) {
	dst := &SecurityContext{}
	src := &SecurityContext{
		Bearer: &BearerAuth{Token: "token"},
		APIKey: &APIKeyAuth{Key: "key"},
	}

	MergeSecurityContext(dst, src)

	if dst.Bearer == nil || dst.Bearer.Token != "token" {
		t.Error("expected Bearer to be merged")
	}
	if dst.APIKey == nil || dst.APIKey.Key != "key" {
		t.Error("expected APIKey to be merged")
	}
}

func TestMatchPath(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		path     string
		expected bool
	}{
		{"exact match", "/pets", "/pets", true},
		{"exact no match", "/pets", "/users", false},
		{"param match", "/pets/{id}", "/pets/123", true},
		{"param match with string", "/pets/{id}", "/pets/fluffy", true},
		{"param no match extra segment", "/pets/{id}", "/pets/123/extra", false},
		{"param no match missing segment", "/pets/{id}", "/pets", false},
		{"multiple params", "/users/{userId}/pets/{petId}", "/users/1/pets/2", true},
		{"trailing slash pattern", "/pets/", "/pets/", true},
		{"trailing slash mismatch", "/pets", "/pets/", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchPath(tt.pattern, tt.path)
			if got != tt.expected {
				t.Errorf("matchPath(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.expected)
			}
		})
	}
}
