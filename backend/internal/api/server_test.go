package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// clientIP feeds an inet column, so a malformed result fails the audit insert
// and takes the whole request with it. IPv6 is the case that bites: a naive
// split on ":" turns "[::1]:54321" into "[".
func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		forwarded  string
		want       string
	}{
		{"ipv4", "192.0.2.10:54321", "", "192.0.2.10"},
		{"ipv6 loopback", "[::1]:54321", "", "::1"},
		{"ipv6 full", "[2001:db8::8a2e:370:7334]:443", "", "2001:db8::8a2e:370:7334"},
		{"no port", "192.0.2.10", "", "192.0.2.10"},
		{"forwarded single", "10.0.0.1:1234", "203.0.113.5", "203.0.113.5"},
		{"forwarded chain", "10.0.0.1:1234", "203.0.113.5, 10.0.0.1", "203.0.113.5"},
		{"forwarded with spaces", "10.0.0.1:1234", "  203.0.113.5  ", "203.0.113.5"},
		{"empty forwarded falls back", "192.0.2.10:80", "", "192.0.2.10"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &http.Request{RemoteAddr: tc.remoteAddr, Header: http.Header{}}
			if tc.forwarded != "" {
				r.Header.Set("X-Forwarded-For", tc.forwarded)
			}
			if got := clientIP(r); got != tc.want {
				t.Errorf("clientIP(%q, fwd=%q) = %q, want %q", tc.remoteAddr, tc.forwarded, got, tc.want)
			}
		})
	}
}

func TestBearerToken(t *testing.T) {
	tests := []struct {
		name   string
		header string
		cookie string
		want   string
	}{
		{"bearer header", "Bearer abc123", "", "abc123"},
		{"bearer with spaces", "Bearer   abc123  ", "", "abc123"},
		{"cookie fallback", "", "cookie-token", "cookie-token"},
		{"header wins over cookie", "Bearer header-token", "cookie-token", "header-token"},
		{"no credentials", "", "", ""},
		{"wrong scheme is ignored", "Basic dXNlcjpwYXNz", "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &http.Request{Header: http.Header{}}
			if tc.header != "" {
				r.Header.Set("Authorization", tc.header)
			}
			if tc.cookie != "" {
				r.AddCookie(&http.Cookie{Name: "skm_session", Value: tc.cookie})
			}
			if got := bearerToken(r); got != tc.want {
				t.Errorf("bearerToken() = %q, want %q", got, tc.want)
			}
		})
	}
}

// The event stream has to work through the *whole* middleware chain, not just
// when the handler is called directly. It did not: the logging middleware's
// response wrapper did not implement http.Flusher, so the handler's type
// assertion failed and every stream returned 500. Nothing caught it until the
// interface was opened in a browser.
func TestStatusRecorderForwardsFlush(t *testing.T) {
	rec := httptest.NewRecorder()
	wrapped := &statusRecorder{ResponseWriter: rec}

	if _, ok := any(wrapped).(http.Flusher); !ok {
		t.Fatal("statusRecorder does not implement http.Flusher; the event stream cannot work behind it")
	}

	// Unwrap is what lets http.ResponseController reach the real writer, which
	// is how a streaming handler clears its write deadline.
	unwrapper, ok := any(wrapped).(interface{ Unwrap() http.ResponseWriter })
	if !ok {
		t.Fatal("statusRecorder does not implement Unwrap; ResponseController cannot reach the real writer")
	}
	if unwrapper.Unwrap() != http.ResponseWriter(rec) {
		t.Error("Unwrap did not return the underlying writer")
	}

	// Flushing must reach the recorder rather than panicking or silently
	// dropping.
	if _, err := wrapped.Write([]byte("data: hello\n\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	wrapped.Flush()

	if !rec.Flushed {
		t.Error("Flush did not reach the underlying writer")
	}
	if got := rec.Body.String(); got != "data: hello\n\n" {
		t.Errorf("body = %q", got)
	}
}

// A must-change-password session is a session that can do one thing. The list
// of exceptions is short on purpose; anything added to it is a way to use the
// application with a password somebody else chose.
func TestAllowedBeforePasswordChange(t *testing.T) {
	allowed := []string{
		"GET /api/v1/auth/me",
		"POST /api/v1/auth/logout",
		"POST /api/v1/auth/password",
	}
	blocked := []string{
		"GET /api/v1/keys",
		"POST /api/v1/keys",
		"GET /api/v1/dashboard",
		"POST /api/v1/auth/step-up",
		"POST /api/v1/auth/totp/enrol",
		"GET /api/v1/auth/password",
		"POST /api/v1/users/abc/password",
	}
	for _, key := range allowed {
		method, path, _ := strings.Cut(key, " ")
		if !allowedBeforePasswordChange(method, path) {
			t.Errorf("%s should be allowed before a password change", key)
		}
	}
	for _, key := range blocked {
		method, path, _ := strings.Cut(key, " ")
		if allowedBeforePasswordChange(method, path) {
			t.Errorf("%s should be blocked before a password change", key)
		}
	}
}
