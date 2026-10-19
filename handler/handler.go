package handler

import (
	"context"
	"fmt"
	"net/http"
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
}

func (h *Handler) Init(conf *util.Configuration, logger *util.Logger, db *dal.Database, sv *service.Service, authCodeStore *util.AuthorizationCodeStore, tk *token.Token) {
	h.conf = conf
	h.logger = logger
	h.db = db
	h.sv = sv
	h.authCodeStore = authCodeStore
	h.tk = tk
}

func (h *Handler) ListenAndServe() error {
	mux := http.NewServeMux()
	mux.Handle("/health", h.corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		responseOk(w)
	})))
	mux.Handle("/setup/admin-login", h.middlewares(http.MethodPost, h.adminLogin))
	mux.Handle("/setup/admin-logout", h.middlewares(http.MethodPost, h.adminLogout))
	mux.Handle("/setup/register", h.middlewares(http.MethodPost, h.register))
	mux.Handle("/setup/client-list", h.middlewares(http.MethodGet, h.clientList))
	mux.Handle("/setup/client-create", h.middlewares(http.MethodPost, h.clientCreate))
	mux.Handle("/setup/client-delete", h.middlewares(http.MethodDelete, h.clientDelete))
	mux.Handle("/.well-known/openid-configuration", h.middlewares(http.MethodGet, h.oidcDiscovery))
	mux.Handle("/.well-known/jwks.json", h.middlewares(http.MethodGet, h.oidcJWKS))
	mux.Handle("/authorize", h.middlewares(http.MethodGet, h.oidcAuthorize))
	mux.Handle("/token", h.middlewares(http.MethodPost, h.oidcToken))
	mux.Handle("/userinfo", h.middlewares(http.MethodGet, h.oidcUserinfo))
	mux.Handle("/auth/login", h.middlewares(http.MethodPost, h.login))
	h.server = &http.Server{
		Addr:              h.conf.HttpAddress,
		Handler:           mux,
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

func (h *Handler) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
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

		ipAddress := r.Header.Get("X-Real-Ip")
		if ipAddress == "" {
			ipAddress = r.Header.Get("X-Forwarded-For")
		}
		if ipAddress == "" {
			ipAddress = r.RemoteAddr
		}
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
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
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
