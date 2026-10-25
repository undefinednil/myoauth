package util

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
)

type Configuration struct {
	HttpAddress                string             `json:"httpAddress"`
	AllowedOrigins             []string           `json:"allowedOrigins"`
	SecureCookies              bool               `json:"secureCookies"`
	OidcIssuer                 string             `json:"oidcIssuer"`
	OidcLoginUrl               string             `json:"oidcLoginUrl"`
	InvitationCode             string             `json:"invitationCode"`
	AdminPassword              string             `json:"adminPassword"`
	AuthorizationCodeLength    int                `json:"authorizationCodeLength"`
	RefreshTokenLength         int                `json:"refreshTokenLength"`
	PasswordMinLength          int                `json:"passwordMinLength"`
	DbPath                     string             `json:"dbPath"`
	LogFilePath                string             `json:"logFilePath"`
	RsaPrivateKeyPath          string             `json:"rsaPrivateKeyPath"`
	RateLimitEnabled           *bool              `json:"rateLimitEnabled"`
	RateLimitRequestsPerMinute int                `json:"rateLimitRequestsPerMinute"`
	RateLimitBurst             int                `json:"rateLimitBurst"`
	RateLimitMaxKeys           int                `json:"rateLimitMaxKeys"`
	TrustProxy                 bool               `json:"trustProxy"`
	ForwardAuth                *ForwardAuthConfig `json:"forwardAuth"`
}

// ForwardAuthConfig configures the built-in OIDC forward-auth service that
// replaces oauth2-proxy's `auth_request` role. The whole feature is opt-in: a
// nil value (or enabled=false) keeps the server behaving exactly as before.
type ForwardAuthConfig struct {
	Enabled                bool     `json:"enabled"`
	ClientId               string   `json:"clientId"`
	ClientSecret           string   `json:"clientSecret"`
	CookieSecret           string   `json:"cookieSecret"`
	CookieName             string   `json:"cookieName"`
	CookieDomain           string   `json:"cookieDomain"`
	CookieSecure           bool     `json:"cookieSecure"`
	SessionTtlSeconds      int      `json:"sessionTtlSeconds"`
	LoginPath              string   `json:"loginPath"`
	CallbackPath           string   `json:"callbackPath"`
	AuthPath               string   `json:"authPath"`
	SignOutPath            string   `json:"signOutPath"`
	AllowedRedirectDomains []string `json:"allowedRedirectDomains"`
}

func (c *Configuration) Init(path string) error {
	confJson, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(confJson, &c); err != nil {
		return err
	}
	if strings.TrimSpace(c.OidcIssuer) == "" {
		return errors.New("oidcIssuer is required")
	}
	// An empty admin password makes the admin session HMAC key empty, allowing
	// forged admin sessions and defeating CSRF (FIX F6).
	if strings.TrimSpace(c.AdminPassword) == "" {
		return errors.New("adminPassword is required")
	}
	c.OidcIssuer = strings.TrimSuffix(strings.TrimSpace(c.OidcIssuer), "/")
	c.applyDefaults()
	if err := c.validateForwardAuth(); err != nil {
		return err
	}
	return nil
}

func (c *Configuration) applyDefaults() {
	if c.RateLimitEnabled == nil {
		enabled := true
		c.RateLimitEnabled = &enabled
	}
	if c.RateLimitRequestsPerMinute <= 0 {
		c.RateLimitRequestsPerMinute = 30
	}
	if c.RateLimitBurst <= 0 {
		c.RateLimitBurst = 10
	}
	if c.RateLimitMaxKeys <= 0 {
		c.RateLimitMaxKeys = 100000
	}
	if c.ForwardAuth != nil {
		fa := c.ForwardAuth
		if strings.TrimSpace(fa.ClientId) == "" {
			fa.ClientId = "proxy"
		}
		if strings.TrimSpace(fa.CookieName) == "" {
			fa.CookieName = "_myoauth_proxy"
		}
		if strings.TrimSpace(fa.LoginPath) == "" {
			fa.LoginPath = "/oauth2/start"
		}
		if strings.TrimSpace(fa.CallbackPath) == "" {
			fa.CallbackPath = "/oauth2/callback"
		}
		if strings.TrimSpace(fa.AuthPath) == "" {
			fa.AuthPath = "/oauth2/auth"
		}
		if strings.TrimSpace(fa.SignOutPath) == "" {
			fa.SignOutPath = "/oauth2/sign_out"
		}
	}
}

func (c *Configuration) validateForwardAuth() error {
	fa := c.ForwardAuth
	if fa == nil || !fa.Enabled {
		return nil
	}
	if strings.TrimSpace(fa.ClientSecret) == "" {
		return errors.New("forwardAuth.clientSecret is required when forwardAuth is enabled")
	}
	if strings.TrimSpace(fa.CookieSecret) == "" {
		return errors.New("forwardAuth.cookieSecret is required when forwardAuth is enabled")
	}
	// A short cookie secret would weaken AES-256-GCM, whose key is derived from
	// it, so refuse to boot (FIX-style fail fast).
	if len(fa.CookieSecret) < 32 {
		return errors.New("forwardAuth.cookieSecret must be at least 32 characters")
	}
	return nil
}

// RateLimitingEnabled reports whether the request rate limiter is active. A
// missing config value defaults to enabled.
func (c *Configuration) RateLimitingEnabled() bool {
	return c.RateLimitEnabled == nil || *c.RateLimitEnabled
}
