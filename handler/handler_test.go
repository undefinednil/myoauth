package handler

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cristalhq/jwt/v5"
	"github.com/undefinednil/myoauth/dal"
	"github.com/undefinednil/myoauth/service"
	"github.com/undefinednil/myoauth/token"
	"github.com/undefinednil/myoauth/util"
)

const (
	testClientId     = "test-client"
	testClientSecret = "super-secret"
	testRedirectURI  = "https://app.example.com/callback"
	testUserUuid     = "user-uuid-1"

	// testAdminPassword is the admin password the harness configures.
	// Configuration.Init now requires MYOAUTH_ADMIN_PASSWORD to already be a
	// bcrypt hash, so the env value is the cost-4 hash below; cost 4 is valid
	// bcrypt and keeps the suite fast.
	testAdminPassword     = "admin-secret"
	testAdminPasswordHash = "$2a$04$uGlZM7JsZO2hIaO9XoKUteu34GIME7QYmH2mnhTvnxQyUxjrodHNe"

	// testInvitationCode must be at least 16 characters, as enforced by
	// Configuration.Init.
	testInvitationCode = "test-invitation-code"
)

// myOauthEnvKeys lists every MYOAUTH_* variable the server reads. Tests blank
// them all so an ambient value cannot leak in; t.Setenv restores the originals
// afterwards.
var myOauthEnvKeys = []string{
	"MYOAUTH_HTTP_ADDRESS",
	"MYOAUTH_OIDC_ISSUER",
	"MYOAUTH_OIDC_LOGIN_URL",
	"MYOAUTH_INVITATION_CODE",
	"MYOAUTH_ADMIN_PASSWORD",
	"MYOAUTH_DB_PATH",
	"MYOAUTH_LOG_FILE_PATH",
	"MYOAUTH_RSA_PRIVATE_KEY_PATH",
	"MYOAUTH_ALLOWED_ORIGINS",
	"MYOAUTH_SECURE_COOKIES",
	"MYOAUTH_TRUST_PROXY",
	"MYOAUTH_PASSWORD_MIN_LENGTH",
	"MYOAUTH_AUTHORIZATION_CODE_LENGTH",
	"MYOAUTH_REFRESH_TOKEN_LENGTH",
	"MYOAUTH_RATE_LIMIT_ENABLED",
	"MYOAUTH_RATE_LIMIT_REQUESTS_PER_MINUTE",
	"MYOAUTH_RATE_LIMIT_BURST",
	"MYOAUTH_RATE_LIMIT_MAX_KEYS",
	"MYOAUTH_FORWARD_AUTH_ENABLED",
	"MYOAUTH_FORWARD_AUTH_CLIENT_ID",
	"MYOAUTH_FORWARD_AUTH_CLIENT_SECRET",
	"MYOAUTH_FORWARD_AUTH_COOKIE_SECRET",
	"MYOAUTH_FORWARD_AUTH_COOKIE_NAME",
	"MYOAUTH_FORWARD_AUTH_COOKIE_DOMAIN",
	"MYOAUTH_FORWARD_AUTH_COOKIE_SECURE",
	"MYOAUTH_FORWARD_AUTH_SESSION_TTL_SECONDS",
	"MYOAUTH_FORWARD_AUTH_ALLOWED_CALLBACK_ORIGINS",
	"MYOAUTH_FORWARD_AUTH_ALLOWED_REDIRECT_DOMAINS",
}

// clearMyOauthEnv blanks every MYOAUTH_* variable so a variable from the
// surrounding shell cannot leak into a handler test.
func clearMyOauthEnv(t *testing.T) {
	t.Helper()
	for _, key := range myOauthEnvKeys {
		t.Setenv(key, "")
	}
}

func newTestHandler(t *testing.T) (*Handler, *util.Configuration) {
	t.Helper()
	return newTestHandlerWithEnv(t, nil)
}

// newTestHandlerWithEnv is newTestHandler plus a set of per-test MYOAUTH_*
// overrides (e.g. the forwardAuth block), applied on top of a minimal baseline.
// The RSA key path is intentionally left absent so token.Init auto-generates it.
func newTestHandlerWithEnv(t *testing.T, overrides map[string]string) (*Handler, *util.Configuration) {
	t.Helper()
	dir := t.TempDir()

	clearMyOauthEnv(t)
	t.Setenv("MYOAUTH_HTTP_ADDRESS", "127.0.0.1:0")
	t.Setenv("MYOAUTH_OIDC_ISSUER", "https://issuer.example.com")
	t.Setenv("MYOAUTH_OIDC_LOGIN_URL", "https://issuer.example.com/login")
	t.Setenv("MYOAUTH_INVITATION_CODE", testInvitationCode)
	t.Setenv("MYOAUTH_ADMIN_PASSWORD", testAdminPasswordHash)
	t.Setenv("MYOAUTH_AUTHORIZATION_CODE_LENGTH", "48")
	t.Setenv("MYOAUTH_REFRESH_TOKEN_LENGTH", "48")
	t.Setenv("MYOAUTH_PASSWORD_MIN_LENGTH", "8")
	t.Setenv("MYOAUTH_DB_PATH", filepath.Join(dir, "test.db"))
	t.Setenv("MYOAUTH_LOG_FILE_PATH", filepath.Join(dir, "test.log"))
	t.Setenv("MYOAUTH_RSA_PRIVATE_KEY_PATH", filepath.Join(dir, "private.pem"))
	for k, v := range overrides {
		t.Setenv(k, v)
	}

	conf := new(util.Configuration)
	if err := conf.Init(); err != nil {
		t.Fatalf("conf.Init: %v", err)
	}

	logger := new(util.Logger)
	if err := logger.Init(conf); err != nil {
		t.Fatalf("logger.Init: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	db := new(dal.Database)
	if err := db.Init(t.Context(), conf); err != nil {
		t.Fatalf("db.Init: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	tk := new(token.Token)
	if err := tk.Init(conf, logger); err != nil {
		t.Fatalf("token.Init: %v", err)
	}

	sv := new(service.Service)
	sv.Init(conf, db)

	h := new(Handler)
	h.Init(conf, logger, db, sv, util.NewAuthorizationCodeStore(conf), tk,
		util.NewDenylist(), util.NewRateLimiter(conf.RateLimitRequestsPerMinute, conf.RateLimitBurst, conf.RateLimitMaxKeys))
	return h, conf
}

func seedClientAndUser(t *testing.T, h *Handler) (*dal.Client, *dal.User) {
	t.Helper()
	secretHash, err := util.BCryptPassword(testClientSecret)
	if err != nil {
		t.Fatalf("BCryptPassword: %v", err)
	}
	if err := h.db.Clients.Insert(t.Context(), &dal.Client{
		ClientId:        testClientId,
		Secret:          secretHash,
		Redirects:       testRedirectURI,
		AccessTokenAge:  1,
		RefreshTokenAge: 720,
	}); err != nil {
		t.Fatalf("insert client: %v", err)
	}
	client, err := h.db.Clients.SelectByClientId(t.Context(), testClientId)
	if err != nil || client == nil {
		t.Fatalf("select client: %v", err)
	}
	if err := h.db.Users.Insert(t.Context(), &dal.User{Uuid: testUserUuid, Name: "alice", Password: secretHash}); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	user, err := h.db.Users.SelectByName(t.Context(), "alice")
	if err != nil || user == nil {
		t.Fatalf("select user: %v", err)
	}
	return client, user
}

func challengeOf(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func postForm(t *testing.T, endpoint, clientId, secret string, form url.Values) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientId, secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func decodeJWTClaims(t *testing.T, raw string) map[string]any {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("expected a JWT, got %q", raw)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	claims := map[string]any{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return claims
}

func noRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func TestDiscoveryIncludesNewEndpoints(t *testing.T) {
	h, _ := newTestHandler(t)
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("get discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body := map[string]any{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	for _, field := range []string{"end_session_endpoint", "revocation_endpoint", "introspection_endpoint"} {
		if body[field] == nil || body[field] == "" {
			t.Errorf("discovery missing %s", field)
		}
	}
	claims, _ := body["claims_supported"].([]any)
	have := map[string]bool{}
	for _, c := range claims {
		if s, ok := c.(string); ok {
			have[s] = true
		}
	}
	for _, want := range []string{"auth_time", "nonce", "at_hash", "c_hash"} {
		if !have[want] {
			t.Errorf("discovery claims_supported missing %s", want)
		}
	}
}

func seedSecondClient(t *testing.T, h *Handler) *dal.Client {
	t.Helper()
	secretHash, err := util.BCryptPassword("secret-2")
	if err != nil {
		t.Fatalf("BCryptPassword: %v", err)
	}
	if err := h.db.Clients.Insert(t.Context(), &dal.Client{
		ClientId:        "client-2",
		Secret:          secretHash,
		Redirects:       "https://other.example.com/cb",
		AccessTokenAge:  1,
		RefreshTokenAge: 720,
	}); err != nil {
		t.Fatalf("insert second client: %v", err)
	}
	client, err := h.db.Clients.SelectByClientId(t.Context(), "client-2")
	if err != nil || client == nil {
		t.Fatalf("select second client: %v", err)
	}
	return client
}

func userinfoStatus(t *testing.T, srvURL, token string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, srvURL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// F3/F7: an ID token is not accepted as an access token, and malformed tokens
// yield 401 rather than 500.
func TestIDTokenRejectedAsAccessToken(t *testing.T) {
	h, _ := newTestHandler(t)
	client, user := seedClientAndUser(t, h)
	accessToken, _, err := h.issueAccessToken(t.Context(), user, client, "openid")
	if err != nil {
		t.Fatal(err)
	}
	idToken, err := h.issueIDToken(user, client, "", accessToken, "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	if code := userinfoStatus(t, srv.URL, idToken); code != http.StatusUnauthorized {
		t.Fatalf("userinfo with id_token = %d, want 401", code)
	}
	if _, body := postForm(t, srv.URL+"/introspect", testClientId, testClientSecret, url.Values{"token": {idToken}}); body["active"] != false {
		t.Fatalf("introspect id_token active = %v, want false", body["active"])
	}
	// Revoking an id_token must not revoke a real access token.
	if status, _ := postForm(t, srv.URL+"/revoke", testClientId, testClientSecret, url.Values{"token": {idToken}}); status != http.StatusOK {
		t.Fatalf("revoke id_token status = %d, want 200", status)
	}
	if _, body := postForm(t, srv.URL+"/introspect", testClientId, testClientSecret, url.Values{"token": {accessToken}}); body["active"] != true {
		t.Fatalf("access token unexpectedly inactive after revoking id_token: %v", body)
	}
}

func TestUserinfoMalformedTokensReturn401(t *testing.T) {
	h, _ := newTestHandler(t)
	client, user := seedClientAndUser(t, h)
	accessToken, _, err := h.issueAccessToken(t.Context(), user, client, "openid")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	if code := userinfoStatus(t, srv.URL, "not-a-jwt"); code != http.StatusUnauthorized {
		t.Fatalf("garbage token = %d, want 401", code)
	}
	// Flip a character inside the signature segment. Avoid the final base64
	// character: its unused low bits do not affect the decoded signature, so
	// changing it is not necessarily a tamper.
	i := len(accessToken) - 10
	replacement := byte('A')
	if accessToken[i] == 'A' {
		replacement = 'B'
	}
	tampered := accessToken[:i] + string(replacement) + accessToken[i+1:]
	if code := userinfoStatus(t, srv.URL, tampered); code != http.StatusUnauthorized {
		t.Fatalf("tampered token = %d, want 401", code)
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://issuer.example.com","sub":"user-uuid-1","aud":"test-client","token_use":"access","exp":9999999999}`))
	noneToken := header + "." + payload + "."
	if code := userinfoStatus(t, srv.URL, noneToken); code != http.StatusUnauthorized {
		t.Fatalf("alg:none token = %d, want 401", code)
	}
}

// F2: a client cannot introspect or revoke another client's tokens.
func TestCrossClientIntrospectAndRevoke(t *testing.T) {
	h, _ := newTestHandler(t)
	client, user := seedClientAndUser(t, h)
	seedSecondClient(t, h)
	accessToken, _, err := h.issueAccessToken(t.Context(), user, client, "openid")
	if err != nil {
		t.Fatal(err)
	}
	refreshToken, err := h.sv.GenAndInsertRefreshToken(t.Context(), client, user, "openid profile")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	if _, body := postForm(t, srv.URL+"/introspect", "client-2", "secret-2", url.Values{"token": {accessToken}}); body["active"] != false {
		t.Fatalf("cross-client access introspect active = %v, want false", body["active"])
	}
	if _, body := postForm(t, srv.URL+"/introspect", "client-2", "secret-2", url.Values{"token": {refreshToken}}); body["active"] != false {
		t.Fatalf("cross-client refresh introspect active = %v, want false", body["active"])
	}
	if status, _ := postForm(t, srv.URL+"/revoke", "client-2", "secret-2", url.Values{"token": {accessToken}}); status != http.StatusOK {
		t.Fatalf("cross-client revoke status = %d, want 200", status)
	}
	if status, _ := postForm(t, srv.URL+"/revoke", "client-2", "secret-2", url.Values{"token": {refreshToken}}); status != http.StatusOK {
		t.Fatalf("cross-client refresh revoke status = %d, want 200", status)
	}
	if _, body := postForm(t, srv.URL+"/introspect", testClientId, testClientSecret, url.Values{"token": {accessToken}}); body["active"] != true {
		t.Fatalf("owner access introspect after cross-client revoke = %v, want true", body["active"])
	}
	if _, body := postForm(t, srv.URL+"/introspect", testClientId, testClientSecret, url.Values{"token": {refreshToken}}); body["active"] != true {
		t.Fatalf("owner refresh introspect after cross-client revoke = %v, want true", body["active"])
	}
}

// F4: refresh scope cannot be escalated and the granted scope is preserved.
func TestRefreshScopeEscalationRejected(t *testing.T) {
	h, _ := newTestHandler(t)
	client, user := seedClientAndUser(t, h)
	refreshToken, err := h.sv.GenAndInsertRefreshToken(t.Context(), client, user, "openid profile")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	status, body := postForm(t, srv.URL+"/token", testClientId, testClientSecret, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"scope":         {"openid profile admin"},
	})
	if status != http.StatusBadRequest || body["error"] != "invalid_scope" {
		t.Fatalf("scope escalation = %d %v, want 400 invalid_scope", status, body)
	}

	// The stored scope is used when the request omits scope, and the rejected
	// request did not consume the token.
	status, body = postForm(t, srv.URL+"/token", testClientId, testClientSecret, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	})
	if status != http.StatusOK {
		t.Fatalf("refresh status = %d, body = %v", status, body)
	}
	if body["scope"] != "openid profile" {
		t.Fatalf("default scope = %v, want %q", body["scope"], "openid profile")
	}
	rotated, _ := body["refresh_token"].(string)

	// A narrower requested scope is allowed.
	status, body = postForm(t, srv.URL+"/token", testClientId, testClientSecret, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rotated},
		"scope":         {"openid"},
	})
	if status != http.StatusOK || body["scope"] != "openid" {
		t.Fatalf("narrowed scope = %d %v, want 200 openid", status, body)
	}
}

// F12: refresh-issued ID tokens omit auth_time.
func TestRefreshIDTokenOmitsAuthTime(t *testing.T) {
	h, _ := newTestHandler(t)
	client, user := seedClientAndUser(t, h)
	refreshToken, err := h.sv.GenAndInsertRefreshToken(t.Context(), client, user, "openid profile")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	_, body := postForm(t, srv.URL+"/token", testClientId, testClientSecret, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	})
	idToken, _ := body["id_token"].(string)
	if idToken == "" {
		t.Fatalf("expected id_token, got %v", body)
	}
	claims := decodeJWTClaims(t, idToken)
	if _, ok := claims["auth_time"]; ok {
		t.Error("refresh-issued id_token must omit auth_time")
	}
	if claims["token_use"] != token.TokenUseID {
		t.Errorf("token_use = %v, want %q", claims["token_use"], token.TokenUseID)
	}
}

// F5: a mismatched client/hint must not revoke the other client's sessions.
func TestLogoutMismatchedHintDoesNotRevoke(t *testing.T) {
	h, _ := newTestHandler(t)
	client, user := seedClientAndUser(t, h)
	other := seedSecondClient(t, h)
	refreshToken, err := h.sv.GenAndInsertRefreshToken(t.Context(), client, user, "openid profile")
	if err != nil {
		t.Fatal(err)
	}
	accessToken, _, err := h.issueAccessToken(t.Context(), user, client, "openid")
	if err != nil {
		t.Fatal(err)
	}
	idToken, err := h.issueIDToken(user, client, "", accessToken, "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	httpClient := noRedirectClient()
	resp, err := httpClient.Get(srv.URL + "/logout?id_token_hint=" + url.QueryEscape(idToken) + "&client_id=" + other.ClientId)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("mismatched hint status = %d, want 400", resp.StatusCode)
	}
	remaining, err := h.db.RefreshTokens.SelectByToken(t.Context(), refreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if remaining == nil {
		t.Fatal("mismatched client/hint must not revoke the token")
	}
}

// F8: a malformed id_token_hint is a 400, not a 500, and revokes nothing.
func TestLogoutMalformedHintReturns400(t *testing.T) {
	h, _ := newTestHandler(t)
	client, user := seedClientAndUser(t, h)
	refreshToken, err := h.sv.GenAndInsertRefreshToken(t.Context(), client, user, "openid profile")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	httpClient := noRedirectClient()
	resp, err := httpClient.Get(srv.URL + "/logout?id_token_hint=not-a-jwt&client_id=" + client.ClientId)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed hint status = %d, want 400", resp.StatusCode)
	}
	remaining, err := h.db.RefreshTokens.SelectByToken(t.Context(), refreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if remaining == nil {
		t.Fatal("malformed hint must not revoke the token")
	}
}

// F9: session-revoke invalidates an outstanding access token.
func TestSessionRevokeInvalidatesAccessToken(t *testing.T) {
	h, _ := newTestHandler(t)
	client, user := seedClientAndUser(t, h)
	accessToken, _, err := h.issueAccessToken(t.Context(), user, client, "openid")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	session, csrf := adminSessionForTest(t, h)
	if status := adminRequest(t, srv.URL+"/setup/session-revoke", session, csrf, csrf, fmt.Sprintf(`{"clientId":%d}`, client.Id)); status != http.StatusOK {
		t.Fatalf("session-revoke status = %d, want 200", status)
	}
	if code := userinfoStatus(t, srv.URL, accessToken); code != http.StatusUnauthorized {
		t.Fatalf("userinfo after session-revoke = %d, want 401", code)
	}
	if _, body := postForm(t, srv.URL+"/introspect", testClientId, testClientSecret, url.Values{"token": {accessToken}}); body["active"] != false {
		t.Fatalf("introspect after session-revoke = %v, want false", body["active"])
	}
}

// F9: revocation survives the loss of the in-memory denylist.
func TestRevocationDurableAfterRestart(t *testing.T) {
	h, _ := newTestHandler(t)
	client, user := seedClientAndUser(t, h)
	accessToken, _, err := h.issueAccessToken(t.Context(), user, client, "openid")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	if status, _ := postForm(t, srv.URL+"/revoke", testClientId, testClientSecret, url.Values{"token": {accessToken}}); status != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200", status)
	}
	// Simulate a restart by dropping the in-memory cache; the DB must still
	// report the token as revoked.
	h.denylist = util.NewDenylist()
	if code := userinfoStatus(t, srv.URL, accessToken); code != http.StatusUnauthorized {
		t.Fatalf("userinfo after restart = %d, want 401", code)
	}
	if _, body := postForm(t, srv.URL+"/introspect", testClientId, testClientSecret, url.Values{"token": {accessToken}}); body["active"] != false {
		t.Fatalf("introspect after restart = %v, want false", body["active"])
	}
}

// F1: spoofed X-Forwarded-For must not bypass the limiter when trustProxy is
// false, but distinct forwarded IPs get distinct buckets when it is true.
func TestRateLimitProxyTrust(t *testing.T) {
	h, conf := newTestHandler(t)
	seedClientAndUser(t, h)
	enabled := true
	conf.RateLimitEnabled = &enabled
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	sendLogin := func(xff string) int {
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/setup/admin-login", strings.NewReader(`{"adminPassword":"wrong"}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", xff)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	conf.TrustProxy = false
	h.rateLimiter = util.NewRateLimiter(60, 1, 100)
	if code := sendLogin("1.1.1.1"); code == http.StatusTooManyRequests {
		t.Fatalf("first request should be allowed, got %d", code)
	}
	if code := sendLogin("2.2.2.2"); code != http.StatusTooManyRequests {
		t.Fatalf("spoofed XFF bypassed limiter with trustProxy=false: got %d", code)
	}

	conf.TrustProxy = true
	h.rateLimiter = util.NewRateLimiter(60, 1, 100)
	if code := sendLogin("1.1.1.1, 3.3.3.3"); code == http.StatusTooManyRequests {
		t.Fatalf("trusted first forwarded IP should be allowed, got %d", code)
	}
	if code := sendLogin("2.2.2.2, 4.4.4.4"); code == http.StatusTooManyRequests {
		t.Fatalf("distinct trusted forwarded IP should get its own bucket, got %d", code)
	}
}

func TestClientIPResolution(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:5555"
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.1")
	req.Header.Set("X-Real-Ip", "9.9.9.9")

	if got := clientIP(req, false); got != "10.0.0.1" {
		t.Fatalf("untrusted clientIP = %q, want 10.0.0.1", got)
	}
	if got := clientIP(req, true); got != "9.9.9.9" {
		t.Fatalf("trusted clientIP = %q, want 9.9.9.9", got)
	}
	req.Header.Del("X-Real-Ip")
	if got := clientIP(req, true); got != "10.0.0.1" {
		t.Fatalf("trusted right-most XFF = %q, want 10.0.0.1", got)
	}

	// Non-IP forwarding values must be ignored (otherwise rotating junk XFF
	// keys bypasses the limiter) and resolution must fall back to the peer.
	junk := httptest.NewRequest(http.MethodGet, "/", nil)
	junk.RemoteAddr = "10.0.0.3:5555"
	junk.Header.Set("X-Real-Ip", "not-an-ip")
	junk.Header.Set("X-Forwarded-For", "%%%, ###, also-bad")
	if got := clientIP(junk, true); got != "10.0.0.3" {
		t.Fatalf("junk forwarding clientIP = %q, want peer 10.0.0.3", got)
	}

	// A valid entry among junk is still honored.
	mixed := httptest.NewRequest(http.MethodGet, "/", nil)
	mixed.RemoteAddr = "10.0.0.4:5555"
	mixed.Header.Set("X-Forwarded-For", "junk, 7.7.7.7, more-junk")
	if got := clientIP(mixed, true); got != "7.7.7.7" {
		t.Fatalf("mixed forwarding clientIP = %q, want 7.7.7.7", got)
	}
}

func TestNormalizeScopeDeduplicates(t *testing.T) {
	if got := normalizeScope("openid openid profile openid"); got != "openid profile" {
		t.Fatalf("normalizeScope dedup = %q, want %q", got, "openid profile")
	}
	if got := normalizeScope("openid"); got != "openid" {
		t.Fatalf("normalizeScope single = %q, want %q", got, "openid")
	}
	if got := normalizeScope("   "); got != "openid profile" {
		t.Fatalf("normalizeScope empty = %q, want default", got)
	}
}

func TestAuthorizeValidationAndRedirect(t *testing.T) {
	h, conf := newTestHandler(t)
	seedClientAndUser(t, h)
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	// Missing required params -> 400.
	resp, err := http.Get(srv.URL + "/authorize")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing params status = %d, want 400", resp.StatusCode)
	}

	// Disallowed redirect_uri -> 400.
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {testClientId},
		"redirect_uri":          {"https://evil.example.com/cb"},
		"scope":                 {"openid"},
		"state":                 {"st"},
		"code_challenge":        {challengeOf(strings.Repeat("a", 48))},
		"code_challenge_method": {"S256"},
	}
	resp, err = http.Get(srv.URL + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad redirect status = %d, want 400", resp.StatusCode)
	}

	// Valid request -> redirect to the login URL.
	q.Set("redirect_uri", testRedirectURI)
	client := noRedirectClient()
	resp, err = client.Get(srv.URL + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("valid authorize status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, conf.OidcLoginUrl) {
		t.Fatalf("login redirect = %q, want prefix %q", loc, conf.OidcLoginUrl)
	}
}

func TestAuthorizationCodeTokenEndpoint(t *testing.T) {
	h, _ := newTestHandler(t)
	client, user := seedClientAndUser(t, h)
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	verifier := strings.Repeat("a", 48)
	code, err := h.authCodeStore.Generate(util.AuthorizationInfo{
		ClientId:      client.Id,
		UserId:        user.Id,
		RedirectUri:   testRedirectURI,
		Scope:         "openid profile",
		State:         "st",
		Nonce:         "n-1",
		CodeChallenge: challengeOf(verifier),
	})
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}

	status, body := postForm(t, srv.URL+"/token", testClientId, testClientSecret, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {testRedirectURI},
	})
	if status != http.StatusOK {
		t.Fatalf("token status = %d, body = %v", status, body)
	}
	accessToken, _ := body["access_token"].(string)
	idToken, _ := body["id_token"].(string)
	if accessToken == "" || idToken == "" {
		t.Fatalf("expected access_token and id_token, got %v", body)
	}
	claims := decodeJWTClaims(t, idToken)
	if claims["nonce"] != "n-1" {
		t.Errorf("nonce = %v, want n-1", claims["nonce"])
	}
	if _, ok := claims["auth_time"]; !ok {
		t.Error("id_token missing auth_time")
	}
	if _, ok := claims["c_hash"]; !ok {
		t.Error("id_token missing c_hash on code exchange")
	}
	if got, _ := claims["at_hash"].(string); got != token.OIDCHash(accessToken) {
		t.Errorf("at_hash = %q, want %q", got, token.OIDCHash(accessToken))
	}
}

func TestRefreshTokenGrantReturnsIDToken(t *testing.T) {
	h, _ := newTestHandler(t)
	client, user := seedClientAndUser(t, h)
	refreshToken, err := h.sv.GenAndInsertRefreshToken(t.Context(), client, user, "openid profile")
	if err != nil {
		t.Fatalf("insert refresh: %v", err)
	}
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	status, body := postForm(t, srv.URL+"/token", testClientId, testClientSecret, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	})
	if status != http.StatusOK {
		t.Fatalf("refresh status = %d, body = %v", status, body)
	}
	idToken, _ := body["id_token"].(string)
	if idToken == "" {
		t.Fatalf("expected id_token on refresh, got %v", body)
	}
	claims := decodeJWTClaims(t, idToken)
	if _, ok := claims["nonce"]; ok {
		t.Error("refresh id_token must not contain nonce")
	}
	if _, ok := claims["c_hash"]; ok {
		t.Error("refresh id_token must not contain c_hash")
	}
	if _, ok := claims["at_hash"]; !ok {
		t.Error("refresh id_token missing at_hash")
	}
}

func TestIntrospectAndRevokeAccessToken(t *testing.T) {
	h, _ := newTestHandler(t)
	client, user := seedClientAndUser(t, h)
	accessToken, _, err := h.issueAccessToken(t.Context(), user, client, "openid profile")
	if err != nil {
		t.Fatalf("issue access token: %v", err)
	}
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	status, body := postForm(t, srv.URL+"/introspect", testClientId, testClientSecret, url.Values{"token": {accessToken}})
	if status != http.StatusOK || body["active"] != true {
		t.Fatalf("introspect active = %v (status %d), want true", body["active"], status)
	}
	if body["client_id"] != testClientId {
		t.Errorf("client_id = %v, want %s", body["client_id"], testClientId)
	}
	if body["sub"] != testUserUuid {
		t.Errorf("sub = %v, want %s", body["sub"], testUserUuid)
	}

	status, _ = postForm(t, srv.URL+"/revoke", testClientId, testClientSecret, url.Values{"token": {accessToken}})
	if status != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200", status)
	}

	_, body = postForm(t, srv.URL+"/introspect", testClientId, testClientSecret, url.Values{"token": {accessToken}})
	if body["active"] != false {
		t.Fatalf("introspect after revoke = %v, want false", body["active"])
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("userinfo with revoked token status = %d, want 401", resp.StatusCode)
	}
}

func TestIntrospectAndRevokeRefreshToken(t *testing.T) {
	h, _ := newTestHandler(t)
	client, user := seedClientAndUser(t, h)
	refreshToken, err := h.sv.GenAndInsertRefreshToken(t.Context(), client, user, "openid profile")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	status, body := postForm(t, srv.URL+"/introspect", testClientId, testClientSecret, url.Values{"token": {refreshToken}})
	if status != http.StatusOK || body["active"] != true {
		t.Fatalf("refresh introspect = %v (status %d), want active", body["active"], status)
	}
	if body["client_id"] != testClientId || body["sub"] != testUserUuid {
		t.Fatalf("unexpected refresh introspection: %v", body)
	}

	status, _ = postForm(t, srv.URL+"/revoke", testClientId, testClientSecret, url.Values{"token": {refreshToken}})
	if status != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200", status)
	}
	_, body = postForm(t, srv.URL+"/introspect", testClientId, testClientSecret, url.Values{"token": {refreshToken}})
	if body["active"] != false {
		t.Fatalf("refresh introspect after revoke = %v, want false", body["active"])
	}
}

func adminRequest(t *testing.T, endpoint, session, csrfCookie, csrfHeader, body string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: adminCookieName, Value: session})
	req.AddCookie(&http.Cookie{Name: adminCSRFCookieName, Value: csrfCookie})
	if csrfHeader != "" {
		req.Header.Set("X-CSRF-Token", csrfHeader)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// adminSessionForTest mints a live server-side admin session directly (as the
// admin-login endpoint would) and returns its id and the CSRF token bound to
// it, so tests can drive authenticated admin endpoints.
func adminSessionForTest(t *testing.T, h *Handler) (string, string) {
	t.Helper()
	session, csrf, err := h.adminSessions.create(adminSessionDuration)
	if err != nil {
		t.Fatalf("create admin session: %v", err)
	}
	return session, csrf
}

// postJSON posts a raw JSON body and returns the status code and decoded body.
func postJSON(t *testing.T, endpoint, body string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Post(endpoint, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post json: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestCSRFRejection(t *testing.T) {
	h, _ := newTestHandler(t)
	seedClientAndUser(t, h)
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	session, csrf := adminSessionForTest(t, h)
	body := `{"clientId":"new-client","secret":"s","redirects":"https://x/cb","accessTokenAge":1,"refreshTokenAge":2}`

	if status := adminRequest(t, srv.URL+"/setup/client-create", session, csrf, "", body); status != http.StatusForbidden {
		t.Fatalf("missing CSRF header status = %d, want 403", status)
	}
	if status := adminRequest(t, srv.URL+"/setup/client-create", session, csrf, "wrong", body); status != http.StatusForbidden {
		t.Fatalf("mismatched CSRF header status = %d, want 403", status)
	}
	if status := adminRequest(t, srv.URL+"/setup/client-create", session, csrf, csrf, body); status != http.StatusOK {
		t.Fatalf("valid CSRF header status = %d, want 200", status)
	}
}

func TestSessionRevokeEndpoint(t *testing.T) {
	h, _ := newTestHandler(t)
	client, user := seedClientAndUser(t, h)
	refreshToken, err := h.sv.GenAndInsertRefreshToken(t.Context(), client, user, "openid profile")
	if err != nil {
		t.Fatal(err)
	}
	before, err := h.db.RefreshTokens.SelectByToken(t.Context(), refreshToken)
	if err != nil || before == nil {
		t.Fatalf("expected refresh token before revoke (err=%v)", err)
	}
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	session, csrf := adminSessionForTest(t, h)
	status := adminRequest(t, srv.URL+"/setup/session-revoke", session, csrf, csrf, fmt.Sprintf(`{"clientId":%d}`, client.Id))
	if status != http.StatusOK {
		t.Fatalf("session-revoke status = %d, want 200", status)
	}
	after, err := h.db.RefreshTokens.SelectByToken(t.Context(), refreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if after != nil {
		t.Fatal("expected refresh token to be deleted")
	}
}

func TestLogoutRedirects(t *testing.T) {
	h, _ := newTestHandler(t)
	client, _ := seedClientAndUser(t, h)
	srv := httptest.NewServer(h.router())
	defer srv.Close()
	httpClient := noRedirectClient()

	// No / disallowed post_logout_redirect_uri -> SPA /logout.
	resp, err := httpClient.Get(srv.URL + "/logout?post_logout_redirect_uri=" + url.QueryEscape("https://evil.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/logout" {
		t.Fatalf("logout disallowed redirect = %d %q, want 302 /logout", resp.StatusCode, resp.Header.Get("Location"))
	}

	// Allowed post_logout_redirect_uri with state.
	resp, err = httpClient.Get(srv.URL + "/logout?client_id=" + client.ClientId +
		"&post_logout_redirect_uri=" + url.QueryEscape(testRedirectURI) + "&state=abc")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	want := testRedirectURI + "?state=abc"
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != want {
		t.Fatalf("logout redirect = %d %q, want 302 %q", resp.StatusCode, resp.Header.Get("Location"), want)
	}
}

func TestLogoutRevokesRefreshTokens(t *testing.T) {
	h, _ := newTestHandler(t)
	client, user := seedClientAndUser(t, h)
	refreshToken, err := h.sv.GenAndInsertRefreshToken(t.Context(), client, user, "openid profile")
	if err != nil {
		t.Fatal(err)
	}
	accessToken, _, err := h.issueAccessToken(t.Context(), user, client, "openid")
	if err != nil {
		t.Fatal(err)
	}
	idToken, err := h.issueIDToken(user, client, "", accessToken, "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	httpClient := noRedirectClient()
	resp, err := httpClient.Get(srv.URL + "/logout?id_token_hint=" + url.QueryEscape(idToken) + "&client_id=" + client.ClientId)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	remaining, err := h.db.RefreshTokens.SelectByToken(t.Context(), refreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if remaining != nil {
		t.Fatal("logout with a valid id_token_hint must revoke refresh tokens")
	}
}

// Logout must also invalidate outstanding access tokens, not just refresh
// tokens.
func TestLogoutRevokesAccessTokens(t *testing.T) {
	h, _ := newTestHandler(t)
	client, user := seedClientAndUser(t, h)
	accessToken, _, err := h.issueAccessToken(t.Context(), user, client, "openid")
	if err != nil {
		t.Fatal(err)
	}
	idToken, err := h.issueIDToken(user, client, "", accessToken, "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	resp, err := noRedirectClient().Get(srv.URL + "/logout?id_token_hint=" + url.QueryEscape(idToken) + "&client_id=" + client.ClientId)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	if code := userinfoStatus(t, srv.URL, accessToken); code != http.StatusUnauthorized {
		t.Fatalf("userinfo with pre-logout access token = %d, want 401", code)
	}
	if _, body := postForm(t, srv.URL+"/introspect", testClientId, testClientSecret, url.Values{"token": {accessToken}}); body["active"] != false {
		t.Fatalf("introspect after logout = %v, want false", body["active"])
	}
}

// OIDC recommends accepting an expired-but-validly-signed id_token_hint for
// logout, while /userinfo keeps rejecting expired access tokens.
func TestLogoutAcceptsExpiredIDTokenHint(t *testing.T) {
	h, _ := newTestHandler(t)
	client, user := seedClientAndUser(t, h)
	refreshToken, err := h.sv.GenAndInsertRefreshToken(t.Context(), client, user, "openid profile")
	if err != nil {
		t.Fatal(err)
	}
	expired := &token.IDTokenClaims{
		TokenUse: token.TokenUseID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    h.tokenIssuer(),
			Subject:   user.Uuid,
			Audience:  jwt.Audience{client.ClientId},
			ExpiresAt: &jwt.NumericDate{Time: time.Now().Add(-time.Hour)},
			IssuedAt:  &jwt.NumericDate{Time: time.Now().Add(-2 * time.Hour)},
		},
	}
	hint, err := h.tk.GenIDToken(expired)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	resp, err := noRedirectClient().Get(srv.URL + "/logout?id_token_hint=" + url.QueryEscape(hint) + "&client_id=" + client.ClientId)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("logout with expired hint = %d, want 302", resp.StatusCode)
	}
	remaining, err := h.db.RefreshTokens.SelectByToken(t.Context(), refreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if remaining != nil {
		t.Fatal("an expired id_token_hint must still revoke refresh tokens")
	}
}

// Introspection reports inactive for a token whose subject user is gone,
// consistent with /userinfo.
func TestIntrospectInactiveForDeletedUser(t *testing.T) {
	h, _ := newTestHandler(t)
	client, user := seedClientAndUser(t, h)
	accessToken, _, err := h.issueAccessToken(t.Context(), user, client, "openid")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.db.Users.DeleteById(t.Context(), user.Id); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	if _, body := postForm(t, srv.URL+"/introspect", testClientId, testClientSecret, url.Values{"token": {accessToken}}); body["active"] != false {
		t.Fatalf("introspect deleted-user token = %v, want false", body["active"])
	}
	if code := userinfoStatus(t, srv.URL, accessToken); code != http.StatusUnauthorized {
		t.Fatalf("userinfo deleted-user token = %d, want 401", code)
	}
}

// TestUserLoginSuccessAndFailure checks the happy path and the hardened failure
// path: an unknown user and a wrong password both return the same 401 body
// (uniform error), so the login endpoint cannot be used for enumeration. It
// also checks that an unsupported scope is rejected before a code is issued.
func TestUserLoginSuccessAndFailure(t *testing.T) {
	h, _ := newTestHandler(t)
	seedClientAndUser(t, h)
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	loginBody := func(username, password, scope string) string {
		return fmt.Sprintf(`{"username":%q,"password":%q,"clientId":%q,"codeChallenge":%q,"redirect":%q,"scope":%q,"state":"st"}`,
			username, password, testClientId, challengeOf(strings.Repeat("v", 48)), testRedirectURI, scope)
	}

	status, body := postJSON(t, srv.URL+"/auth/login", loginBody("alice", testClientSecret, "openid profile"))
	if status != http.StatusOK {
		t.Fatalf("login status = %d, body = %v, want 200", status, body)
	}
	if code, _ := body["authorizationCode"].(string); code == "" {
		t.Fatalf("login response missing authorizationCode: %v", body)
	}

	wrongStatus, wrongBody := postJSON(t, srv.URL+"/auth/login", loginBody("alice", "not-the-password", "openid"))
	unknownStatus, unknownBody := postJSON(t, srv.URL+"/auth/login", loginBody("nobody", "not-the-password", "openid"))
	if wrongStatus != http.StatusUnauthorized || unknownStatus != http.StatusUnauthorized {
		t.Fatalf("failure statuses = %d/%d, want 401/401", wrongStatus, unknownStatus)
	}
	if wrongBody["msg"] != unknownBody["msg"] || wrongBody["msg"] == "" {
		t.Fatalf("failure messages differ: %v vs %v, want one uniform error", wrongBody["msg"], unknownBody["msg"])
	}

	status, _ = postJSON(t, srv.URL+"/auth/login", loginBody("alice", testClientSecret, "openid admin"))
	if status != http.StatusBadRequest {
		t.Fatalf("unsupported scope status = %d, want 400", status)
	}
}

// TestRegisterStatuses covers the invitation-code rejection, a validation
// error and the duplicate-user conflict.
func TestRegisterStatuses(t *testing.T) {
	h, _ := newTestHandler(t)
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	status, body := postJSON(t, srv.URL+"/setup/register", `{"username":"bob","password":"password123","invitationCode":"wrong-code-123456"}`)
	if status != http.StatusForbidden {
		t.Fatalf("wrong invitation status = %d, body = %v, want 403", status, body)
	}
	status, body = postJSON(t, srv.URL+"/setup/register", fmt.Sprintf(`{"username":"bob","password":"x","invitationCode":%q}`, testInvitationCode))
	if status != http.StatusBadRequest {
		t.Fatalf("short password status = %d, body = %v, want 400", status, body)
	}
	status, body = postJSON(t, srv.URL+"/setup/register", fmt.Sprintf(`{"username":"bob","password":"password123","invitationCode":%q}`, testInvitationCode))
	if status != http.StatusOK {
		t.Fatalf("register status = %d, body = %v, want 200", status, body)
	}
	status, body = postJSON(t, srv.URL+"/setup/register", fmt.Sprintf(`{"username":"bob","password":"password123","invitationCode":%q}`, testInvitationCode))
	if status != http.StatusConflict {
		t.Fatalf("duplicate register status = %d, body = %v, want 409", status, body)
	}
}

// TestAdminLoginAndServerSideSession checks the 401 on a wrong admin password,
// that a successful login issues an opaque 256-bit session id, that the CSRF
// token is bound to that session, and that logout revokes the session
// server-side.
func TestAdminLoginAndServerSideSession(t *testing.T) {
	h, _ := newTestHandler(t)
	seedClientAndUser(t, h)
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	status, _ := postJSON(t, srv.URL+"/setup/admin-login", `{"adminPassword":"wrong"}`)
	if status != http.StatusUnauthorized {
		t.Fatalf("wrong admin password status = %d, want 401", status)
	}

	resp, err := http.Post(srv.URL+"/setup/admin-login", "application/json", strings.NewReader(fmt.Sprintf(`{"adminPassword":%q}`, testAdminPassword)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin login status = %d, want 200", resp.StatusCode)
	}
	var session, csrf string
	for _, cookie := range resp.Cookies() {
		switch cookie.Name {
		case adminCookieName:
			session = cookie.Value
		case adminCSRFCookieName:
			csrf = cookie.Value
		}
	}
	if session == "" || csrf == "" {
		t.Fatalf("admin login did not set session cookies (session=%q csrf=%q)", session, csrf)
	}
	// The session id is 256-bit random hex, not the old deterministic HMAC.
	if len(session) != adminSessionIDBytes*2 {
		t.Fatalf("session id length = %d, want %d", len(session), adminSessionIDBytes*2)
	}
	// A CSRF token that does not match the session-bound token is rejected even
	// though cookie and header agree with each other.
	if status := adminRequest(t, srv.URL+"/setup/session-revoke", session, csrf, "deadbeef", `{"clientId":0}`); status != http.StatusForbidden {
		t.Fatalf("forged csrf status = %d, want 403", status)
	}
	if status := adminRequest(t, srv.URL+"/setup/session-revoke", session, csrf, csrf, `{"clientId":0}`); status != http.StatusOK {
		t.Fatalf("authenticated admin action status = %d, want 200", status)
	}
	// Logout must delete the server-side session, so the old cookie stops
	// working immediately.
	if status := adminRequest(t, srv.URL+"/setup/admin-logout", session, csrf, csrf, `{}`); status != http.StatusOK {
		t.Fatalf("admin logout status = %d, want 200", status)
	}
	if status := adminRequest(t, srv.URL+"/setup/session-revoke", session, csrf, csrf, `{"clientId":0}`); status != http.StatusUnauthorized {
		t.Fatalf("session after logout status = %d, want 401", status)
	}
}

// TestClientCreateDuplicateAndRedirectValidation covers the unique-index based
// duplicate detection (409), the redirect-URI validation (400) and the missing
// client on update (404).
func TestClientCreateDuplicateAndRedirectValidation(t *testing.T) {
	h, _ := newTestHandler(t)
	seedClientAndUser(t, h)
	srv := httptest.NewServer(h.router())
	defer srv.Close()
	session, csrf := adminSessionForTest(t, h)

	valid := `{"clientId":"dup-client","secret":"s3cret","redirects":"https://app.example.com/cb","accessTokenAge":1,"refreshTokenAge":2}`
	if status := adminRequest(t, srv.URL+"/setup/client-create", session, csrf, csrf, valid); status != http.StatusOK {
		t.Fatalf("create status = %d, want 200", status)
	}
	if status := adminRequest(t, srv.URL+"/setup/client-create", session, csrf, csrf, valid); status != http.StatusConflict {
		t.Fatalf("duplicate client status = %d, want 409", status)
	}
	for _, bad := range []string{
		`{"clientId":"js-client","secret":"s3cret","redirects":"javascript:alert(1)","accessTokenAge":1,"refreshTokenAge":2}`,
		`{"clientId":"ui-client","secret":"s3cret","redirects":"https://user:pass@app.example.com/cb","accessTokenAge":1,"refreshTokenAge":2}`,
		`{"clientId":"frag-client","secret":"s3cret","redirects":"https://app.example.com/cb#frag","accessTokenAge":1,"refreshTokenAge":2}`,
	} {
		if status := adminRequest(t, srv.URL+"/setup/client-create", session, csrf, csrf, bad); status != http.StatusBadRequest {
			t.Fatalf("invalid redirect status = %d, want 400 (body %s)", status, bad)
		}
	}
	if status := adminRequest(t, srv.URL+"/setup/client-update", session, csrf, csrf, `{"id":9999,"clientId":"nope","redirects":"https://app.example.com/cb","accessTokenAge":1,"refreshTokenAge":2}`); status != http.StatusNotFound {
		t.Fatalf("missing client update status = %d, want 404", status)
	}
}

// TestHealthReportsDatabaseUp checks that /health pings the live database and
// keeps the ok body while the database is reachable.
func TestHealthReportsDatabaseUp(t *testing.T) {
	h, _ := newTestHandler(t)
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d, want 200", resp.StatusCode)
	}
	body := map[string]any{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["ok"] != true {
		t.Fatalf("health body = %v, want ok true", body)
	}
}

// TestSecurityHeadersAndRequestID checks the hardened header set on both JSON
// and SPA responses, the per-request id, and that HSTS is only sent when the
// request actually arrived over TLS.
func TestSecurityHeadersAndRequestID(t *testing.T) {
	h, _ := newTestHandler(t)
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	for _, path := range []string{"/.well-known/openid-configuration", "/"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s: X-Content-Type-Options = %q, want nosniff", path, got)
		}
		if got := resp.Header.Get("X-Frame-Options"); got != "DENY" {
			t.Errorf("%s: X-Frame-Options = %q, want DENY", path, got)
		}
		if got := resp.Header.Get("Referrer-Policy"); got != "no-referrer" {
			t.Errorf("%s: Referrer-Policy = %q, want no-referrer", path, got)
		}
		if got := resp.Header.Get("Content-Security-Policy"); !strings.Contains(got, "frame-ancestors 'none'") {
			t.Errorf("%s: Content-Security-Policy = %q, want a strict policy", path, got)
		}
		if id := resp.Header.Get("X-Request-Id"); len(id) != 16 {
			t.Errorf("%s: X-Request-Id = %q, want 16 hex chars", path, id)
		}
		if got := resp.Header.Get("Strict-Transport-Security"); got != "" {
			t.Errorf("%s: HSTS sent over plain HTTP: %q", path, got)
		}
	}

	tlsSrv := httptest.NewTLSServer(h.router())
	defer tlsSrv.Close()
	resp, err := tlsSrv.Client().Get(tlsSrv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got := resp.Header.Get("Strict-Transport-Security"); got != "max-age=63072000; includeSubDomains" {
		t.Errorf("HTTPS HSTS = %q, want max-age=63072000; includeSubDomains", got)
	}
}

// TestMetricsEndpoint checks the expvar counters are exposed and that a failed
// user login is counted.
func TestMetricsEndpoint(t *testing.T) {
	h, _ := newTestHandler(t)
	seedClientAndUser(t, h)
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	login := fmt.Sprintf(`{"username":"nobody","password":"wrong","clientId":%q,"codeChallenge":%q,"redirect":%q,"scope":"openid","state":"st"}`,
		testClientId, challengeOf(strings.Repeat("v", 48)), testRedirectURI)
	if status, _ := postJSON(t, srv.URL+"/auth/login", login); status != http.StatusUnauthorized {
		t.Fatalf("setup login failure status = %d, want 401", status)
	}

	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics status = %d, want 200", resp.StatusCode)
	}
	body := map[string]any{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode metrics: %v", err)
	}
	for _, want := range []string{"auth_failures_user", "auth_failures_admin", "registrations"} {
		if _, ok := body[want]; !ok {
			t.Errorf("metrics missing %s", want)
		}
	}
	if failures, ok := body["auth_failures_user"].(float64); !ok || failures < 1 {
		t.Errorf("auth_failures_user = %v, want >= 1", body["auth_failures_user"])
	}
}
