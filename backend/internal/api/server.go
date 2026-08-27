package api

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/hamalawy/ssh-key-manager/backend/internal/audit"
	"github.com/hamalawy/ssh-key-manager/backend/internal/authz"
	"github.com/hamalawy/ssh-key-manager/backend/internal/connectors"
	"github.com/hamalawy/ssh-key-manager/backend/internal/events"
	"github.com/hamalawy/ssh-key-manager/backend/internal/jobs"
	"github.com/hamalawy/ssh-key-manager/backend/internal/service"
	"github.com/hamalawy/ssh-key-manager/backend/internal/store"
	"github.com/hamalawy/ssh-key-manager/backend/internal/vault"
)

// Server holds everything the HTTP handlers need.
type Server struct {
	Auth        *service.AuthService
	Keys        *service.KeyService
	Deploy      *service.DeployService
	Rotation    *service.RotationService
	Reconcile   *service.ReconcileService
	Backup      *service.BackupService
	Consumers   *service.ConsumerService
	UserAdmin   *service.UserService
	Worker      *service.Worker
	Targets     *store.Targets
	Assignments *store.Assignments
	Credentials *store.Credentials
	Snapshots   *store.Snapshots
	Users       *store.Users
	Rotations   *store.Rotations
	Jobs        *store.Jobs
	Webhooks    *store.Webhooks
	Backups     *store.Backups
	Discovery   *store.Discovery
	Tokens      *store.Tokens
	Audit       *audit.Logger
	Vault       *vault.Vault
	Registry    *connectors.Registry
	Events      *events.Publisher
	Scheduler   *jobs.Scheduler
	Log         *slog.Logger

	// Issuer names this install in TOTP enrolment URIs.
	Issuer string
	// StaticFS serves the built single-page application when set.
	StaticFS http.Handler
}

type contextKey string

const (
	subjectKey contextKey = "skm.subject"
	tokenKey   contextKey = "skm.token"
)

// subjectFrom returns the authenticated subject for a request.
func subjectFrom(ctx context.Context) *authz.Subject {
	s, _ := ctx.Value(subjectKey).(*authz.Subject)
	return s
}

func tokenFrom(ctx context.Context) string {
	t, _ := ctx.Value(tokenKey).(string)
	return t
}

// Handler builds the full HTTP handler, routes and middleware included.
//
// Every route comes from routes(), which carries its own documentation. That
// is the only way the OpenAPI document and the reference page stay true: they
// are rendered from the same slice the mux is built from, so an endpoint
// cannot exist without being described, and a description cannot survive the
// endpoint it describes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	for _, route := range s.routes() {
		pattern := route.Method + " " + route.Path
		if route.Public {
			mux.HandleFunc(pattern, route.Handler)
			continue
		}
		mux.Handle(pattern, s.requireAuth(route.Handler))
	}

	// The single-page application, when embedded.
	if s.StaticFS != nil {
		mux.Handle("/", s.spaHandler())
	}

	return s.recoverPanic(s.logRequests(s.securityHeaders(mux)))
}

// requireAuth resolves the bearer token into a subject.
func (s *Server) requireAuth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			writeError(w, service.ErrSessionInvalid)
			return
		}

		subject, err := s.Auth.Authenticate(r.Context(), token)
		if err != nil {
			writeError(w, err)
			return
		}
		if subject.TokenID == nil && subject.MustChangePassword && !allowedBeforePasswordChange(r.Method, r.URL.Path) {
			writeError(w, service.ErrPasswordChangeRequired)
			return
		}

		ctx := context.WithValue(r.Context(), subjectKey, subject)
		ctx = context.WithValue(ctx, tokenKey, token)
		next(w, r.WithContext(ctx))
	})
}

// allowedBeforePasswordChange lists what a session may do while its account is
// flagged must_change_password: find out who it is, change the password, or
// leave. API tokens are not gated — they are minted deliberately by an account
// that already signed in, and blocking automation on a flag it cannot clear
// would only break things silently.
func allowedBeforePasswordChange(method, path string) bool {
	switch method + " " + path {
	case "GET /api/v1/auth/me", "POST /api/v1/auth/logout", "POST /api/v1/auth/password":
		return true
	}
	return false
}

// bearerToken extracts the token from the Authorization header, falling back to
// a cookie so the SPA can use an HttpOnly session.
func bearerToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		if after, found := strings.CutPrefix(h, "Bearer "); found {
			return strings.TrimSpace(after)
		}
	}
	if c, err := r.Cookie("skm_session"); err == nil {
		return c.Value
	}
	return ""
}

// securityHeaders applies defensive response headers.
//
// The CSP is restrictive by design: the SPA is self-contained, so there is no
// legitimate reason for it to load scripts or connect anywhere else.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; font-src 'self' data:; connect-src 'self'; "+
				"frame-ancestors 'none'; base-uri 'self'; form-action 'self'")

		// Anything returning key material must never be cached.
		if strings.Contains(r.URL.Path, "/reveal") || strings.Contains(r.URL.Path, "/auth/") {
			h.Set("Cache-Control", "no-store, no-cache, must-revalidate")
			h.Set("Pragma", "no-cache")
		}
		next.ServeHTTP(w, r)
	})
}

// statusRecorder captures the response status for logging.
//
// It must forward the optional ResponseWriter interfaces, not just embed the
// writer: without Flush, the Server-Sent Events handler's type assertion fails
// and the live stream never works at all — a failure invisible in tests that
// call the handler directly rather than through the middleware chain.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

// Flush forwards to the underlying writer so streaming responses reach the
// client instead of sitting in a buffer.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the real writer, which is how a
// streaming handler clears its write deadline.
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}

		next.ServeHTTP(rec, r)

		if rec.status == 0 {
			rec.status = http.StatusOK
		}
		// Health checks would otherwise dominate the log.
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			return
		}

		// A client that navigated away is not a server problem, and logging it
		// at the same level as a real failure trains people to ignore the log.
		if r.Context().Err() != nil {
			s.Log.Debug("request abandoned by the client",
				"method", r.Method, "path", r.URL.Path,
				"duration", time.Since(start).Round(time.Millisecond))
			return
		}

		s.Log.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"bytes", rec.bytes,
			"duration", time.Since(start).Round(time.Millisecond),
			"remote", clientIP(r))
	})
}

// recoverPanic keeps one bad request from taking down the process.
func (s *Server) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.Log.Error("panic in handler", "path", r.URL.Path, "panic", rec)
				writeJSON(w, http.StatusInternalServerError,
					ErrorBody{Error: "an internal error occurred", Code: "panic"})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// spaHandler serves the embedded application, falling back to index.html so
// client-side routes survive a page reload.
func (s *Server) spaHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// An unmatched /api path is a missing endpoint, not a client route.
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeJSON(w, http.StatusNotFound, ErrorBody{Error: "no such endpoint", Code: "not_found"})
			return
		}
		s.StaticFS.ServeHTTP(w, r)
	})
}

// clientIP extracts the caller's address for the audit trail.
//
// net.SplitHostPort is used rather than splitting on ":" because an IPv6
// RemoteAddr looks like "[::1]:54321"; naive splitting yields "[", which is not
// a valid inet value and fails the audit insert.
func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		first, _, _ := strings.Cut(fwd, ",")
		if ip := strings.TrimSpace(first); ip != "" {
			return ip
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// handleHealth reports that the process is alive.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

// handleReady reports whether the server can actually serve traffic.
//
// A sealed vault is reported as not ready: the process is running, but it
// cannot perform key operations, and a load balancer should know that.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	sealed := s.Vault.IsSealed()
	status := http.StatusOK
	if sealed {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, map[string]any{
		"status":       map[bool]string{true: "sealed", false: "ready"}[sealed],
		"vault_sealed": sealed,
	})
}
