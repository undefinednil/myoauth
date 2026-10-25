package handler

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cristalhq/jwt/v5"
	"github.com/zenpk/my-oauth/dal"
	"github.com/zenpk/my-oauth/service"
	"github.com/zenpk/my-oauth/token"
	"github.com/zenpk/my-oauth/util"
)

const (
	testClientId     = "test-client"
	testClientSecret = "super-secret"
	testRedirectURI  = "https://app.example.com/callback"
	testUserUuid     = "user-uuid-1"
)

func newTestHandler(t *testing.T) (*Handler, *util.Configuration) {
	t.Helper()
	return newTestHandlerWithConfig(t, "")
}

// newTestHandlerWithConfig is newTestHandler plus an extra raw JSON fragment
// injected at the end of the config object (e.g. a forwardAuth block). The
// fragment must include a leading comma when non-empty.
func newTestHandlerWithConfig(t *testing.T, extraConfig string) (*Handler, *util.Configuration) {
	t.Helper()
	dir := t.TempDir()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyPath := filepath.Join(dir, "private.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if err := os.WriteFile(keyPath, pemBytes, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	confJSON := fmt.Sprintf(`{
  "httpAddress": "127.0.0.1:0",
  "oidcIssuer": "https://issuer.example.com",
  "oidcLoginUrl": "https://issuer.example.com/login",
  "invitationCode": "test-invite",
  "adminPassword": "admin-secret",
  "authorizationCodeLength": 48,
  "refreshTokenLength": 48,
  "passwordMinLength": 8,
  "dbPath": %q,
  "logFilePath": %q,
  "rsaPrivateKeyPath": %q%s
}`, filepath.Join(dir, "test.db"), filepath.Join(dir, "test.log"), keyPath, extraConfig)
	confPath := filepath.Join(dir, "conf.json")
	if err := os.WriteFile(confPath, []byte(confJSON), 0o600); err != nil {
		t.Fatalf("write conf: %v", err)
	}

	conf := new(util.Configuration)
	if err := conf.Init(confPath); err != nil {
		t.Fatalf("conf.Init: %v", err)
	}

	logger := new(util.Logger)
	if err := logger.Init(conf); err != nil {
		t.Fatalf("logger.Init: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	db := new(dal.Database)
	if err := db.Init(conf); err != nil {
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
	if err := h.db.Clients.Insert(&dal.Client{
		ClientId:        testClientId,
		Secret:          secretHash,
		Redirects:       testRedirectURI,
		AccessTokenAge:  1,
		RefreshTokenAge: 720,
	}); err != nil {
		t.Fatalf("insert client: %v", err)
	}
	client, err := h.db.Clients.SelectByClientId(testClientId)
	if err != nil || client == nil {
		t.Fatalf("select client: %v", err)
	}
	if err := h.db.Users.Insert(&dal.User{Uuid: testUserUuid, Name: "alice", Password: secretHash}); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	user, err := h.db.Users.SelectByName("alice")
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
	if err := h.db.Clients.Insert(&dal.Client{
		ClientId:        "client-2",
		Secret:          secretHash,
		Redirects:       "https://other.example.com/cb",
		AccessTokenAge:  1,
		RefreshTokenAge: 720,
	}); err != nil {
		t.Fatalf("insert second client: %v", err)
	}
	client, err := h.db.Clients.SelectByClientId("client-2")
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
	accessToken, _, err := h.issueAccessToken(user, client, "openid")
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
	accessToken, _, err := h.issueAccessToken(user, client, "openid")
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
	accessToken, _, err := h.issueAccessToken(user, client, "openid")
	if err != nil {
		t.Fatal(err)
	}
	refreshToken, err := h.sv.GenAndInsertRefreshToken(client, user, "openid profile")
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
	refreshToken, err := h.sv.GenAndInsertRefreshToken(client, user, "openid profile")
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
	refreshToken, err := h.sv.GenAndInsertRefreshToken(client, user, "openid profile")
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
	refreshToken, err := h.sv.GenAndInsertRefreshToken(client, user, "openid profile")
	if err != nil {
		t.Fatal(err)
	}
	accessToken, _, err := h.issueAccessToken(user, client, "openid")
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
	remaining, err := h.db.RefreshTokens.SelectByToken(refreshToken)
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
	refreshToken, err := h.sv.GenAndInsertRefreshToken(client, user, "openid profile")
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
	remaining, err := h.db.RefreshTokens.SelectByToken(refreshToken)
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
	accessToken, _, err := h.issueAccessToken(user, client, "openid")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	session := h.signAdminToken(time.Now().Add(time.Hour))
	csrf := "12341234123412341234123412341234"
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
	accessToken, _, err := h.issueAccessToken(user, client, "openid")
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
	refreshToken, err := h.sv.GenAndInsertRefreshToken(client, user, "openid profile")
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
	accessToken, _, err := h.issueAccessToken(user, client, "openid profile")
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
	refreshToken, err := h.sv.GenAndInsertRefreshToken(client, user, "openid profile")
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

func TestCSRFRejection(t *testing.T) {
	h, _ := newTestHandler(t)
	seedClientAndUser(t, h)
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	session := h.signAdminToken(time.Now().Add(time.Hour))
	csrf := "0123456789abcdef0123456789abcdef"
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
	refreshToken, err := h.sv.GenAndInsertRefreshToken(client, user, "openid profile")
	if err != nil {
		t.Fatal(err)
	}
	before, err := h.db.RefreshTokens.SelectByToken(refreshToken)
	if err != nil || before == nil {
		t.Fatalf("expected refresh token before revoke (err=%v)", err)
	}
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	session := h.signAdminToken(time.Now().Add(time.Hour))
	csrf := "abcdefabcdefabcdefabcdefabcdef12"
	status := adminRequest(t, srv.URL+"/setup/session-revoke", session, csrf, csrf, fmt.Sprintf(`{"clientId":%d}`, client.Id))
	if status != http.StatusOK {
		t.Fatalf("session-revoke status = %d, want 200", status)
	}
	after, err := h.db.RefreshTokens.SelectByToken(refreshToken)
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
	refreshToken, err := h.sv.GenAndInsertRefreshToken(client, user, "openid profile")
	if err != nil {
		t.Fatal(err)
	}
	accessToken, _, err := h.issueAccessToken(user, client, "openid")
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

	remaining, err := h.db.RefreshTokens.SelectByToken(refreshToken)
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
	accessToken, _, err := h.issueAccessToken(user, client, "openid")
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
	refreshToken, err := h.sv.GenAndInsertRefreshToken(client, user, "openid profile")
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
	remaining, err := h.db.RefreshTokens.SelectByToken(refreshToken)
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
	accessToken, _, err := h.issueAccessToken(user, client, "openid")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.db.Users.DeleteById(user.Id); err != nil {
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
