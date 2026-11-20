// Package api implements the REST API (see api/openapi.yaml), the SSE event
// stream and serves the embedded web UI.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/tinybrickboy/yourcve/internal/ai"
	"github.com/tinybrickboy/yourcve/internal/auth"
	"github.com/tinybrickboy/yourcve/internal/catalog"
	"github.com/tinybrickboy/yourcve/internal/config"
	"github.com/tinybrickboy/yourcve/internal/cvedb"
	"github.com/tinybrickboy/yourcve/internal/jobs"
	"github.com/tinybrickboy/yourcve/internal/notify"
)

type Server struct {
	Cfg      *config.Config
	Pool     *pgxpool.Pool
	Log      *slog.Logger
	Auth     *auth.Service
	CVEs     *cvedb.Store
	Catalog  *catalog.Store
	River    *jobs.Client
	Sealer   *notify.Sealer
	Sender   *notify.Sender
	Notifier *notify.Notifier
	Mailer   *notify.Mailer // nil without SMTP
	AI       *ai.Enricher   // nil without Ollama
	Hub      *Hub
	MCP      http.Handler
	Web      http.Handler
	Ready    func() bool

	imprint, privacy string
}

var metricHTTP = prometheus.NewHistogramVec(prometheus.HistogramOpts{
	Name: "yourcve_http_request_duration_seconds", Help: "HTTP request latency.",
	Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 10}}, []string{"route", "code"})

func init() { prometheus.MustRegister(metricHTTP) }

type ctxKey int

const (
	userKey ctxKey = iota
	viaKey
)

func userFrom(ctx context.Context) *auth.User {
	u, _ := ctx.Value(userKey).(*auth.User)
	return u
}

func (s *Server) Handler() http.Handler {
	if s.Cfg.ImprintFile != "" {
		b, _ := os.ReadFile(s.Cfg.ImprintFile)
		s.imprint = string(b)
	}
	if s.Cfg.PrivacyFile != "" {
		b, _ := os.ReadFile(s.Cfg.PrivacyFile)
		s.privacy = string(b)
	}
	mux := http.NewServeMux()
	pub := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, s.instrument(pattern, h)) }
	priv := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, s.instrument(pattern, s.requireUser(h))) }

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /readyz", s.readyz)
	mux.Handle("GET /metrics", promhttp.Handler())

	pub("GET /v1/config", s.getConfig)
	pub("GET /v1/plans", s.getPlans)
	pub("GET /v1/channel-types", s.getChannelTypes)

	pub("GET /v1/auth/altcha", s.altcha)
	pub("POST /v1/auth/register", s.register)
	pub("POST /v1/auth/magic-link", s.magicLink)
	pub("GET /v1/auth/verify", s.verify)
	pub("POST /v1/auth/logout", s.logout)
	pub("POST /v1/auth/passkey/login/begin", s.passkeyLoginBegin)
	pub("POST /v1/auth/passkey/login/finish", s.passkeyLoginFinish)
	priv("POST /v1/auth/passkey/register/begin", s.passkeyRegisterBegin)
	priv("POST /v1/auth/passkey/register/finish", s.passkeyRegisterFinish)

	priv("GET /v1/me", s.getMe)
	priv("DELETE /v1/me", s.deleteMe)
	priv("GET /v1/passkeys", s.listPasskeys)
	priv("DELETE /v1/passkeys/{id}", s.deletePasskey)
	priv("GET /v1/apikeys", s.listAPIKeys)
	priv("POST /v1/apikeys", s.createAPIKey)
	priv("DELETE /v1/apikeys/{id}", s.deleteAPIKey)

	pub("GET /v1/cves", s.searchCVEs)
	pub("GET /v1/cves/{id}", s.getCVE)
	priv("POST /v1/search/semantic", s.semanticSearch)
	pub("GET /v1/products", s.searchProducts)

	priv("GET /v1/stacks", s.listStacks)
	priv("POST /v1/stacks", s.createStack)
	priv("GET /v1/stacks/{id}", s.getStack)
	priv("PATCH /v1/stacks/{id}", s.renameStack)
	priv("DELETE /v1/stacks/{id}", s.deleteStack)
	priv("POST /v1/stacks/{id}/items", s.addItem)
	priv("PATCH /v1/stacks/{id}/items/{item}", s.updateItem)
	priv("DELETE /v1/stacks/{id}/items/{item}", s.deleteItem)
	priv("POST /v1/stacks/{id}/import", s.importStack)
	priv("GET /v1/stacks/{id}/cves", s.stackCVEs)
	priv("PUT /v1/stacks/{id}/cves/{cve}/status", s.setCVEStatus)

	priv("GET /v1/channels", s.listChannels)
	priv("POST /v1/channels", s.createChannel)
	priv("DELETE /v1/channels/{id}", s.deleteChannel)
	priv("POST /v1/channels/{id}/test", s.testChannel)
	pub("GET /v1/channels/confirm", s.confirmChannel)
	pub("GET /v1/unsubscribe", s.unsubscribe)
	pub("POST /v1/unsubscribe", s.unsubscribe) // RFC 8058 one-click

	priv("GET /v1/rules", s.listRules)
	priv("POST /v1/rules", s.createRule)
	priv("PATCH /v1/rules/{id}", s.updateRule)
	priv("DELETE /v1/rules/{id}", s.deleteRule)

	priv("GET /v1/deliveries", s.listDeliveries)
	priv("POST /v1/deliveries/{id}/retry", s.retryDelivery)
	priv("GET /v1/credits", s.getCredits)
	priv("GET /v1/events", s.events)
	priv("GET /v1/admin/status", s.adminStatus)

	if s.MCP != nil {
		mux.Handle("/mcp", s.requireAPIUser(s.MCP))
	}
	mux.Handle("/v1/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, http.StatusNotFound, "not found")
	}))
	if s.Web != nil {
		mux.Handle("/", s.Web)
	}
	return s.recoverer(s.securityHeaders(s.authenticate(s.csrf(mux))))
}

// ---------------------------------------------------------------- middleware

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(c int) { w.code = c; w.ResponseWriter.WriteHeader(c) }
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (s *Server) instrument(route string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, code: 200}
		h.ServeHTTP(sw, r)
		metricHTTP.WithLabelValues(route, strconv.Itoa(sw.code)).Observe(time.Since(start).Seconds())
		if sw.code >= 500 {
			s.Log.Warn("http error", "method", r.Method, "path", r.URL.Path, "code", sw.code)
		}
	})
}

func (s *Server) recoverer(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				s.Log.Error("panic", "err", v, "stack", string(debug.Stack()))
				writeErr(w, http.StatusInternalServerError, "internal error")
			}
		}()
		h.ServeHTTP(w, r)
	})
}

func (s *Server) securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		hd.Set("X-Frame-Options", "DENY")
		if !strings.HasPrefix(r.URL.Path, "/v1/") && r.URL.Path != "/mcp" {
			hd.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; worker-src 'self' blob:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		}
		if s.Cfg.SecureCookies() {
			hd.Set("Strict-Transport-Security", "max-age=31536000")
		}
		h.ServeHTTP(w, r)
	})
}

func (s *Server) authenticate(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/") || r.URL.Path == "/mcp" {
			u, via, err := s.Auth.Authenticate(r.Context(), r)
			if err != nil {
				s.Log.Error("authenticate", "err", err)
			}
			if u != nil {
				ctx := context.WithValue(r.Context(), userKey, u)
				ctx = context.WithValue(ctx, viaKey, via)
				r = r.WithContext(ctx)
			}
		}
		h.ServeHTTP(w, r)
	})
}

// csrf: state changing requests authenticated by cookie must come from our origin.
func (s *Server) csrf(h http.Handler) http.Handler {
	base, _ := url.Parse(s.Cfg.BaseURL)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		safe := r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions
		via, _ := r.Context().Value(viaKey).(auth.Via)
		_, hasCookie := r.Cookie(auth.SessionCookie)
		if !safe && via != auth.ViaAPIKey && hasCookie == nil && r.URL.Path != "/v1/unsubscribe" {
			origin := r.Header.Get("Origin")
			site := r.Header.Get("Sec-Fetch-Site")
			ok := site == "same-origin" || site == "none"
			if origin != "" {
				if o, err := url.Parse(origin); err == nil && base != nil {
					ok = o.Scheme == base.Scheme && o.Host == base.Host
				} else {
					ok = false
				}
			} else if site == "" {
				ok = true // non-browser clients
			}
			if !ok {
				writeErr(w, http.StatusForbidden, "cross-site request blocked")
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}

func (s *Server) requireUser(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if userFrom(r.Context()) == nil {
			writeErr(w, http.StatusUnauthorized, "login required")
			return
		}
		h(w, r)
	})
}

func (s *Server) requireAPIUser(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if userFrom(r.Context()) == nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="yourcve"`)
			writeErr(w, http.StatusUnauthorized, "API key required (Authorization: Bearer <key>)")
			return
		}
		h.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------- helpers

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func (s *Server) internal(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, context.Canceled) {
		return
	}
	s.Log.Error("request failed", "method", r.Method, "path", r.URL.Path, "err", err)
	writeErr(w, http.StatusInternalServerError, "internal error")
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

func pathID(w http.ResponseWriter, r *http.Request, name string) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusNotFound, "not found")
		return 0, false
	}
	return id, true
}

func queryInt(r *http.Request, k string, def int) int {
	if v, err := strconv.Atoi(r.URL.Query().Get(k)); err == nil {
		return v
	}
	return def
}

func queryFloat(r *http.Request, k string) *float64 {
	if v, err := strconv.ParseFloat(r.URL.Query().Get(k), 64); err == nil {
		return &v
	}
	return nil
}

func (s *Server) ip(r *http.Request) string { return auth.ClientIP(r, s.Cfg.TrustProxyHeaders) }

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.Pool.Ping(ctx); err != nil || (s.Ready != nil && !s.Ready()) {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	w.Write([]byte("ready\n"))
}

func parseDate(s string) *time.Time {
	for _, l := range []string{time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(l, s); err == nil {
			return &t
		}
	}
	return nil
}
