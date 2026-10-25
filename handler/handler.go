package handler

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/zenpk/my-oauth/dal"
	"github.com/zenpk/my-oauth/service"
	"github.com/zenpk/my-oauth/token"
	"github.com/zenpk/my-oauth/util"
)

type Handler struct {
	server        *http.Server
	db            *dal.Database
	conf          *util.Configuration
	logger        util.ILogger
	sv            *service.Service
	authCodeStore *util.AuthorizationCodeStore
	tk            *token.Token
	denylist      *util.Denylist
	rateLimiter   *util.RateLimiter
	faCodec       *util.SecureCookieCodec
	// faSessions is a pointer so the per-session locks it guards are shared
	// across every (value-receiver) request handler copy.
	faSessions *forwardAuthSessions
}

func (h *Handler) Init(conf *util.Configuration, logger *util.Logger, db *dal.Database, sv *service.Service, authCodeStore *util.AuthorizationCodeStore, tk *token.Token, denylist *util.Denylist, rateLimiter *util.RateLimiter) {
	h.conf = conf
	h.logger = logger
	h.db = db
	h.sv = sv
	h.authCodeStore = authCodeStore
	h.tk = tk
	h.denylist = denylist
	h.rateLimiter = rateLimiter
	if conf.ForwardAuth != nil && conf.ForwardAuth.Enabled {
		codec, err := util.NewSecureCookieCodec(conf.ForwardAuth.CookieSecret)
		if err != nil {
			// The feature is enabled, so silently degrading (and dropping the
			// state-cookie protection) is unsafe: fail fast (FIX G).
			panic("forward auth: could not build cookie codec: " + err.Error())
		}
		h.faCodec = codec
		h.faSessions = newForwardAuthSessions()
	}
}

func (h *Handler) router() *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/health", h.corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		responseOk(w)
	})))
	mux.Handle("/setup/admin-login", h.rateLimitedMiddlewares("admin-login", http.MethodPost, h.adminLogin))
	mux.Handle("/setup/admin-logout", h.middlewares(http.MethodPost, h.adminLogout))
	mux.Handle("/setup/register", h.middlewares(http.MethodPost, h.register))
	mux.Handle("/setup/client-list", h.middlewares(http.MethodGet, h.clientList))
	mux.Handle("/setup/client-create", h.middlewares(http.MethodPost, h.clientCreate))
	mux.Handle("/setup/client-update", h.middlewares(http.MethodPost, h.clientUpdate))
	mux.Handle("/setup/client-delete", h.middlewares(http.MethodDelete, h.clientDelete))
	mux.Handle("/setup/session-revoke", h.middlewares(http.MethodPost, h.sessionRevoke))
	mux.Handle("/.well-known/openid-configuration", h.middlewares(http.MethodGet, h.oidcDiscovery))
	mux.Handle("/.well-known/jwks.json", h.middlewares(http.MethodGet, h.oidcJWKS))
	mux.Handle("/authorize", h.middlewares(http.MethodGet, h.oidcAuthorize))
	mux.Handle("/token", h.rateLimitedMiddlewares("token", http.MethodPost, h.oidcToken))
	mux.Handle("/userinfo", h.middlewares(http.MethodGet, h.oidcUserinfo))
	mux.Handle("/logout", h.middlewares(http.MethodGet, h.oidcLogout))
	mux.Handle("/revoke", h.middlewares(http.MethodPost, h.oidcRevoke))
	mux.Handle("/introspect", h.middlewares(http.MethodPost, h.oidcIntrospect))
	mux.Handle("/auth/login", h.rateLimitedMiddlewares("login", http.MethodPost, h.login))

	// Forward-auth routes are only registered when the feature is enabled; the
	// reserved namespace below still 404s unknown subpaths when it is disabled.
	if h.conf.ForwardAuth != nil && h.conf.ForwardAuth.Enabled && h.faCodec != nil {
		fa := h.conf.ForwardAuth
		mux.Handle(fa.LoginPath, h.middlewares(http.MethodGet, h.forwardAuthLogin))
		mux.Handle(fa.CallbackPath, h.middlewares(http.MethodGet, h.forwardAuthCallback))
		mux.Handle(fa.AuthPath, h.methodsMiddlewares([]string{http.MethodGet, http.MethodHead}, h.forwardAuthAuth))
		mux.Handle(fa.SignOutPath, h.middlewares(http.MethodGet, h.forwardAuthSignOut))
	}

	// Reserved namespaces must never fall through to the SPA catch-all; return
	// a JSON 404 so typo'd API paths are not masked by a 200 HTML page (FIX 4).
	mux.HandleFunc("/setup/", notFoundJSON)
	mux.HandleFunc("/.well-known/", notFoundJSON)
	mux.HandleFunc("/auth/", notFoundJSON)
	mux.HandleFunc("/api/", notFoundJSON)
	mux.HandleFunc("/health/", notFoundJSON)
	mux.HandleFunc("/authorize/", notFoundJSON)
	mux.HandleFunc("/token/", notFoundJSON)
	mux.HandleFunc("/userinfo/", notFoundJSON)
	mux.HandleFunc("/logout/", notFoundJSON)
	mux.HandleFunc("/revoke/", notFoundJSON)
	mux.HandleFunc("/introspect/", notFoundJSON)
	// Register the bare /oauth2 as well so it returns a JSON 404 instead of the
	// ServeMux's automatic 307 redirect to /oauth2/ (FIX F).
	mux.HandleFunc("/oauth2", notFoundJSON)
	mux.HandleFunc("/oauth2/", notFoundJSON)

	mux.Handle("/", h.spaSecurityHeadersMiddleware(h.webHandler()))
	return mux
}

func (h *Handler) ListenAndServe() error {
	h.server = &http.Server{
		Addr:              h.conf.HttpAddress,
		Handler:           h.router(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	h.logger.Printf("start listening at %v\n", h.server.Addr)
	return h.server.ListenAndServe()
}

func (h *Handler) Shutdown(ctx context.Context) error {
	return h.server.Shutdown(ctx)
}

const maxBodySize = 1 << 20 // 1 MB

func (h *Handler) middlewares(method string, handler func(w http.ResponseWriter, r *http.Request)) http.Handler {
	return h.logMiddleware(h.securityHeadersMiddleware(h.corsMiddleware(h.bodySizeLimitMiddleware(h.methodMiddleware(method, http.HandlerFunc(handler))))))
}

// methodsMiddlewares is like middlewares but accepts several HTTP methods
// (used by the forward-auth auth subrequest, which nginx may issue as GET or
// HEAD).
func (h *Handler) methodsMiddlewares(methods []string, handler func(w http.ResponseWriter, r *http.Request)) http.Handler {
	return h.logMiddleware(h.securityHeadersMiddleware(h.corsMiddleware(h.bodySizeLimitMiddleware(methodAnyMiddleware(methods, http.HandlerFunc(handler))))))
}

// rateLimitedMiddlewares applies the same chain as middlewares plus the
// per-endpoint, per-client-IP rate limiter.
func (h *Handler) rateLimitedMiddlewares(endpoint, method string, handler func(w http.ResponseWriter, r *http.Request)) http.Handler {
	return h.logMiddleware(h.securityHeadersMiddleware(h.corsMiddleware(h.bodySizeLimitMiddleware(h.rateLimitMiddleware(endpoint, h.methodMiddleware(method, http.HandlerFunc(handler)))))))
}

func (h *Handler) rateLimitMiddleware(endpoint string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.rateLimiter == nil || !h.conf.RateLimitingEnabled() {
			next.ServeHTTP(w, r)
			return
		}
		// Keys are namespaced per endpoint so the token endpoint cannot drain
		// the login budget (FIX F1).
		key := endpoint + "|" + clientIP(r, h.conf.TrustProxy)
		if !h.rateLimiter.Allow(key) {
			w.Header().Set("Retry-After", strconv.Itoa(h.rateLimiter.RetryAfterSeconds()))
			responseJson(w, commonResp{Ok: false, Msg: "too many requests"}, http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP resolves the originating client IP. Forwarding headers are only
// trusted when trustProxy is set, because X-Forwarded-For is otherwise
// attacker-controlled (FIX F1). When trusted, X-Real-Ip (which the shipped
// nginx overwrites with $remote_addr) is preferred, then the right-most valid
// X-Forwarded-For entry (the closest proxy hop), never the left-most.
// Non-IP forwarding entries are ignored (a client could otherwise rotate junk
// XFF values to evade the limiter) and resolution falls back to the socket
// peer address.
func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if realIP := normalizeIP(r.Header.Get("X-Real-Ip")); realIP != "" {
			return realIP
		}
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			parts := strings.Split(forwarded, ",")
			for i := len(parts) - 1; i >= 0; i-- {
				if ip := normalizeIP(parts[i]); ip != "" {
					return ip
				}
			}
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && host != "" {
		if ip := normalizeIP(host); ip != "" {
			return ip
		}
	}
	if ip := normalizeIP(r.RemoteAddr); ip != "" {
		return ip
	}
	return r.RemoteAddr
}

// normalizeIP strips a port and canonicalizes an IP address so equivalent
// spellings map to the same rate-limit key. It returns "" for anything that is
// not a valid IP, so junk forwarding headers are skipped.
func normalizeIP(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	value = strings.Trim(value, "[]")
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	return ""
}

// applySecurityHeaders sets the two security headers shared by JSON and SPA
// responses. It deliberately does not touch Cache-Control (FIX 3).
func applySecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
}

func (h *Handler) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		applySecurityHeaders(w)
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// spaSecurityHeadersMiddleware applies the security headers to SPA responses
// without the `Cache-Control: no-store` used by the JSON API, so asset caching
// keeps working.
func (h *Handler) spaSecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		applySecurityHeaders(w)
		next.ServeHTTP(w, r)
	})
}

func notFoundJSON(w http.ResponseWriter, r *http.Request) {
	responseJson(w, commonResp{
		Ok:  false,
		Msg: "not found",
	}, http.StatusNotFound)
}

func (h *Handler) bodySizeLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
		next.ServeHTTP(w, r)
	})
}

type statusResponseWriter struct {
	http.ResponseWriter
	statusCode int
	username   string
}

func (s *statusResponseWriter) WriteHeader(statusCode int) {
	s.statusCode = statusCode
	s.ResponseWriter.WriteHeader(statusCode)
}

func (s *statusResponseWriter) WriteUsername(username string) {
	s.username = username
}

func (h *Handler) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusResponseWriter{
			w,
			http.StatusOK,
			"unknown user",
		}

		next.ServeHTTP(sw, r)

		ipAddress := clientIP(r, h.conf.TrustProxy)
		timeNow := time.Now().UTC().Format("2006-01-02 15:04:05") // UTC guaranteed
		h.logger.Printf("%s | %v | %-7s | %v | %v | %v\n", timeNow, sw.statusCode, r.Method, r.URL.Path, ipAddress, sw.username)
	})
}

func (h *Handler) corsMiddleware(next http.Handler) http.Handler {
	allowed := make(map[string]bool, len(h.conf.AllowedOrigins))
	for _, o := range h.conf.AllowedOrigins {
		allowed[o] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && allowed[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token")
		}
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *Handler) methodMiddleware(method string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			data := commonResp{
				Ok:  false,
				Msg: fmt.Sprintf("HTTP method %v is not supported", r.Method),
			}
			responseJson(w, data, http.StatusNotFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func methodAnyMiddleware(methods []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, method := range methods {
			if r.Method == method {
				next.ServeHTTP(w, r)
				return
			}
		}
		data := commonResp{
			Ok:  false,
			Msg: fmt.Sprintf("HTTP method %v is not supported", r.Method),
		}
		responseJson(w, data, http.StatusNotFound)
	})
}
