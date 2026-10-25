package handler

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zenpk/my-oauth/dal"
	"github.com/zenpk/my-oauth/util"
)

const forwardAuthCookieSecret = "0123456789abcdef0123456789abcdef" // 32 chars

func newForwardAuthTestHandler(t *testing.T) (*Handler, *util.Configuration) {
	t.Helper()
	extra := fmt.Sprintf(`,
  "forwardAuth": {
    "enabled": true,
    "clientId": "proxy",
    "clientSecret": "proxy-secret-value",
    "cookieSecret": %q,
    "allowedRedirectDomains": ["allowed.example.com"]
  }`, forwardAuthCookieSecret)
	h, conf := newTestHandlerWithConfig(t, extra)
	if err := h.EnsureForwardAuthClient(); err != nil {
		t.Fatalf("EnsureForwardAuthClient: %v", err)
	}
	return h, conf
}

func forwardAuthCookieFromResp(resp *http.Response, name string) *http.Cookie {
	for _, cookie := range resp.Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

// seedProxySession inserts a server-side session row and returns its opaque id.
func seedProxySession(t *testing.T, h *Handler, user *dal.User, accessToken, refreshToken string, accessExp, exp int64) string {
	t.Helper()
	sessionID, err := util.RandBase64URL(forwardAuthSessionIDBytes)
	if err != nil {
		t.Fatalf("RandBase64URL: %v", err)
	}
	if err := h.db.ProxySessions.Insert(&dal.ProxySession{
		Id:           sessionID,
		UserUuid:     user.Uuid,
		Name:         user.Name,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		AccessExp:    accessExp,
		Exp:          exp,
		CreatedAt:    time.Now().Unix(),
	}); err != nil {
		t.Fatalf("insert proxy session: %v", err)
	}
	return sessionID
}

func forwardAuthRequestE(srvURL, cookieName, sessionID string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, srvURL+"/oauth2/auth", nil)
	if err != nil {
		return nil, err
	}
	if sessionID != "" {
		req.AddCookie(&http.Cookie{Name: cookieName, Value: sessionID})
	}
	return http.DefaultClient.Do(req)
}

func forwardAuthRequest(t *testing.T, srvURL, cookieName, sessionID string) *http.Response {
	t.Helper()
	resp, err := forwardAuthRequestE(srvURL, cookieName, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestForwardAuthStartRedirectsToAuthorize(t *testing.T) {
	h, conf := newForwardAuthTestHandler(t)
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	resp, err := noRedirectClient().Get(srv.URL + "/oauth2/start?rd=/app")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("start status = %d, want 302", resp.StatusCode)
	}

	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, conf.OidcIssuer+"/authorize?") {
		t.Fatalf("start location = %q, want prefix %q", loc, conf.OidcIssuer+"/authorize?")
	}
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	q := parsed.Query()
	if q.Get("client_id") != "proxy" {
		t.Errorf("client_id = %q, want proxy", q.Get("client_id"))
	}
	if q.Get("redirect_uri") != conf.OidcIssuer+"/oauth2/callback" {
		t.Errorf("redirect_uri = %q, want %q", q.Get("redirect_uri"), conf.OidcIssuer+"/oauth2/callback")
	}
	if q.Get("response_type") != "code" {
		t.Errorf("response_type = %q, want code", q.Get("response_type"))
	}
	if q.Get("scope") != "openid profile" {
		t.Errorf("scope = %q, want openid profile", q.Get("scope"))
	}
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		t.Errorf("missing PKCE params: challenge=%q method=%q", q.Get("code_challenge"), q.Get("code_challenge_method"))
	}
	if q.Get("state") == "" {
		t.Error("state is empty")
	}

	stateCookie := forwardAuthCookieFromResp(resp, h.forwardAuthStateCookieName())
	if stateCookie == nil || stateCookie.Value == "" {
		t.Fatal("state cookie was not set")
	}
	if !stateCookie.HttpOnly {
		t.Error("state cookie must be HttpOnly")
	}
	var st forwardAuthState
	if err := h.faCodec.Decode(stateCookie.Value, &st); err != nil {
		t.Fatalf("decode state cookie: %v", err)
	}
	if st.State != q.Get("state") {
		t.Errorf("state cookie = %q, want %q", st.State, q.Get("state"))
	}
	if st.Rd != "/app" {
		t.Errorf("state cookie rd = %q, want /app", st.Rd)
	}
	sum := sha256.Sum256([]byte(st.CodeVerifier))
	if got := base64.RawURLEncoding.EncodeToString(sum[:]); got != q.Get("code_challenge") {
		t.Errorf("code_challenge = %q, want S256 of verifier (%q)", q.Get("code_challenge"), got)
	}
}

func TestForwardAuthStartRejectsOpenRedirect(t *testing.T) {
	h, _ := newForwardAuthTestHandler(t)
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	cases := []struct {
		in   string
		want string
	}{
		{"https://evil.example.com/x", "/"},
		{"//evil.example.com/x", "/"},
		{"/app", "/app"},
		{"/deep/path?q=1", "/deep/path?q=1"},
		{"https://allowed.example.com/ok", "https://allowed.example.com/ok"},
		{"http://allowed.example.com/ok", "http://allowed.example.com/ok"},
		// Arbitrary ports are rejected (FIX D).
		{"http://allowed.example.com:8080/ok", "/"},
		{"https://allowed.example.com:8443/ok", "/"},
		// Default ports on the matching scheme are fine.
		{"https://allowed.example.com:443/ok", "https://allowed.example.com:443/ok"},
		{"http://allowed.example.com:80/ok", "http://allowed.example.com:80/ok"},
		// Userinfo is rejected outright.
		{"https://user:pass@allowed.example.com/x", "/"},
		{"https://allowed.example.com@evil.example.com/x", "/"},
		// Backslash / CRLF / control characters.
		{"/a\\b", "/"},
		{"/a\r\nb", "/"},
		{"/a\x01b", "/"},
		// Percent-encoded separators.
		{"/a%2fb", "/"},
		{"/a%2Fb", "/"},
		{"/a%5cb", "/"},
		{"/a%5Cb", "/"},
		// Non-http(s) schemes.
		{"javascript:alert(1)", "/"},
		{"data:text/html,<script>", "/"},
	}
	for _, tc := range cases {
		resp, err := noRedirectClient().Get(srv.URL + "/oauth2/start?rd=" + url.QueryEscape(tc.in))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		stateCookie := forwardAuthCookieFromResp(resp, h.forwardAuthStateCookieName())
		if stateCookie == nil {
			t.Fatalf("rd=%q: state cookie missing", tc.in)
		}
		var st forwardAuthState
		if err := h.faCodec.Decode(stateCookie.Value, &st); err != nil {
			t.Fatalf("rd=%q: decode state cookie: %v", tc.in, err)
		}
		if st.Rd != tc.want {
			t.Errorf("rd=%q resolved to %q, want %q", tc.in, st.Rd, tc.want)
		}
	}
}

func TestForwardAuthCallbackSetsSession(t *testing.T) {
	h, conf := newForwardAuthTestHandler(t)
	_, user := seedClientAndUser(t, h)
	proxy, err := h.db.Clients.SelectByClientId("proxy")
	if err != nil || proxy == nil {
		t.Fatalf("select proxy client: %v", err)
	}

	verifier := strings.Repeat("a", 64)
	state := "state-abc"
	code, err := h.authCodeStore.Generate(util.AuthorizationInfo{
		ClientId:      proxy.Id,
		UserId:        user.Id,
		RedirectUri:   h.forwardAuthRedirectURI(),
		Scope:         "openid profile",
		State:         state,
		Nonce:         "n-1",
		CodeChallenge: challengeOf(verifier),
	})
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	stateCookie, err := h.faCodec.Encode(forwardAuthState{State: state, CodeVerifier: verifier, Rd: "/app"})
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(h.router())
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/oauth2/callback?code="+url.QueryEscape(code)+"&state="+state, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: h.forwardAuthStateCookieName(), Value: stateCookie})
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback status = %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/app" {
		t.Fatalf("callback location = %q, want /app", loc)
	}

	sessionCookie := forwardAuthCookieFromResp(resp, conf.ForwardAuth.CookieName)
	if sessionCookie == nil || sessionCookie.Value == "" {
		t.Fatal("session cookie was not set")
	}
	if !sessionCookie.HttpOnly {
		t.Error("session cookie must be HttpOnly")
	}
	// The cookie must be an opaque id, not the tokens.
	if strings.Contains(sessionCookie.Value, ".") {
		t.Errorf("session cookie looks like a token, got %q", sessionCookie.Value)
	}
	if len(sessionCookie.Value) < 40 {
		t.Errorf("session cookie id is too short (%d chars), want >=32 random bytes of base64url", len(sessionCookie.Value))
	}

	session, err := h.db.ProxySessions.SelectById(sessionCookie.Value)
	if err != nil {
		t.Fatalf("select session row: %v", err)
	}
	if session == nil {
		t.Fatal("no proxy_sessions row for the session cookie")
	}
	if session.UserUuid != user.Uuid {
		t.Errorf("session user_uuid = %q, want %q", session.UserUuid, user.Uuid)
	}
	if session.Name != "alice" {
		t.Errorf("session name = %q, want alice", session.Name)
	}
	if session.AccessToken == "" || session.RefreshToken == "" {
		t.Error("session must carry access and refresh tokens server-side")
	}
	if session.AccessToken == sessionCookie.Value {
		t.Error("cookie must not contain the access token")
	}
	if session.Exp <= time.Now().Unix() {
		t.Error("session expiry must be in the future")
	}

	cleared := forwardAuthCookieFromResp(resp, h.forwardAuthStateCookieName())
	if cleared == nil || cleared.MaxAge >= 0 {
		t.Error("state cookie must be cleared by the callback")
	}
}

func TestForwardAuthCallbackRejectsStateMismatch(t *testing.T) {
	h, _ := newForwardAuthTestHandler(t)
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	stateCookie, err := h.faCodec.Encode(forwardAuthState{State: "expected", CodeVerifier: strings.Repeat("a", 64), Rd: "/app"})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/oauth2/callback?code=x&state=different", nil)
	req.AddCookie(&http.Cookie{Name: h.forwardAuthStateCookieName(), Value: stateCookie})
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("state mismatch status = %d, want 400", resp.StatusCode)
	}
}

func TestForwardAuthAuthEndpoint(t *testing.T) {
	h, conf := newForwardAuthTestHandler(t)
	_, user := seedClientAndUser(t, h)
	proxy, err := h.db.Clients.SelectByClientId("proxy")
	if err != nil || proxy == nil {
		t.Fatalf("select proxy client: %v", err)
	}
	accessToken, _, err := h.issueAccessToken(user, proxy, "openid profile")
	if err != nil {
		t.Fatal(err)
	}
	refreshToken, err := h.sv.GenAndInsertRefreshToken(proxy, user, "openid profile")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	sessionID := seedProxySession(t, h, user, accessToken, refreshToken, now+3600, now+86400)

	srv := httptest.NewServer(h.router())
	defer srv.Close()

	// No cookie -> 401.
	resp := forwardAuthRequest(t, srv.URL, conf.ForwardAuth.CookieName, "")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("auth without cookie = %d, want 401", resp.StatusCode)
	}

	// Valid id -> 202 + identity headers.
	resp = forwardAuthRequest(t, srv.URL, conf.ForwardAuth.CookieName, sessionID)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("auth with cookie = %d, want 202", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Auth-Request-User"); got != user.Uuid {
		t.Errorf("X-Auth-Request-User = %q, want %q", got, user.Uuid)
	}
	if got := resp.Header.Get("X-Auth-Request-Preferred-Username"); got != "alice" {
		t.Errorf("X-Auth-Request-Preferred-Username = %q, want alice", got)
	}
	if got := resp.Header.Get("X-Auth-Request-Access-Token"); got != accessToken {
		t.Errorf("X-Auth-Request-Access-Token mismatch")
	}
}

func TestForwardAuthAuthRejectsBadCookie(t *testing.T) {
	h, conf := newForwardAuthTestHandler(t)
	_, user := seedClientAndUser(t, h)
	now := time.Now().Unix()
	sessionID := seedProxySession(t, h, user, "at", "rt", now+3600, now+86400)

	srv := httptest.NewServer(h.router())
	defer srv.Close()

	// Unknown/garbage id -> 401.
	for _, id := range []string{"not-a-real-session", sessionID + "x"} {
		resp := forwardAuthRequest(t, srv.URL, conf.ForwardAuth.CookieName, id)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("auth with id %q = %d, want 401", id, resp.StatusCode)
		}
	}

	// Expired session row -> 401 and the row is deleted.
	expiredID := seedProxySession(t, h, user, "at", "rt", now-10, now-1)
	resp := forwardAuthRequest(t, srv.URL, conf.ForwardAuth.CookieName, expiredID)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired session = %d, want 401", resp.StatusCode)
	}
	if row, err := h.db.ProxySessions.SelectById(expiredID); err != nil || row != nil {
		t.Fatalf("expired session must be deleted (row=%v, err=%v)", row, err)
	}
}

// FIX C: expired access token with no refresh token must deny, not 202.
func TestForwardAuthAuthExpiredNoRefreshReturns401(t *testing.T) {
	h, conf := newForwardAuthTestHandler(t)
	_, user := seedClientAndUser(t, h)
	now := time.Now().Unix()
	sessionID := seedProxySession(t, h, user, "stale-access", "", now-10, now+86400)

	srv := httptest.NewServer(h.router())
	defer srv.Close()

	resp := forwardAuthRequest(t, srv.URL, conf.ForwardAuth.CookieName, sessionID)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired access without refresh = %d, want 401", resp.StatusCode)
	}
	if resp.Header.Get("X-Auth-Request-Access-Token") != "" {
		t.Error("a denied response must not expose an access token")
	}
}

// FIX B: client-supplied X-Auth-Request-* headers must be ignored.
func TestForwardAuthAuthIgnoresSpoofedHeaders(t *testing.T) {
	h, conf := newForwardAuthTestHandler(t)
	_, user := seedClientAndUser(t, h)
	proxy, err := h.db.Clients.SelectByClientId("proxy")
	if err != nil || proxy == nil {
		t.Fatalf("select proxy client: %v", err)
	}
	accessToken, _, err := h.issueAccessToken(user, proxy, "openid profile")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	sessionID := seedProxySession(t, h, user, accessToken, "rt", now+3600, now+86400)

	srv := httptest.NewServer(h.router())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/oauth2/auth", nil)
	req.AddCookie(&http.Cookie{Name: conf.ForwardAuth.CookieName, Value: sessionID})
	req.Header.Set("X-Auth-Request-User", "spoofed-admin")
	req.Header.Set("X-Auth-Request-Preferred-Username", "spoofed-user")
	req.Header.Set("X-Auth-Request-Access-Token", "spoofed-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got := resp.Header.Get("X-Auth-Request-User"); got != user.Uuid {
		t.Errorf("spoofed user leaked: got %q, want %q", got, user.Uuid)
	}
	if got := resp.Header.Get("X-Auth-Request-Preferred-Username"); got != "alice" {
		t.Errorf("spoofed preferred username leaked: got %q, want alice", got)
	}
	if got := resp.Header.Get("X-Auth-Request-Access-Token"); got != accessToken {
		t.Errorf("spoofed access token leaked: got %q", got)
	}
}

func TestForwardAuthAuthRefreshesExpiredAccessToken(t *testing.T) {
	h, conf := newForwardAuthTestHandler(t)
	_, user := seedClientAndUser(t, h)
	proxy, err := h.db.Clients.SelectByClientId("proxy")
	if err != nil || proxy == nil {
		t.Fatalf("select proxy client: %v", err)
	}
	oldAccess, _, err := h.issueAccessToken(user, proxy, "openid profile")
	if err != nil {
		t.Fatal(err)
	}
	refreshToken, err := h.sv.GenAndInsertRefreshToken(proxy, user, "openid profile")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	sessionID := seedProxySession(t, h, user, oldAccess, refreshToken, now-10, now+86400)

	srv := httptest.NewServer(h.router())
	defer srv.Close()

	resp := forwardAuthRequest(t, srv.URL, conf.ForwardAuth.CookieName, sessionID)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("auth refresh = %d, want 202", resp.StatusCode)
	}
	newAccess := resp.Header.Get("X-Auth-Request-Access-Token")
	if newAccess == "" || newAccess == oldAccess {
		t.Fatalf("expected a rotated access token, got %q", newAccess)
	}
	// No Set-Cookie is needed: the cookie stays valid because the tokens live
	// server-side.
	if cookie := forwardAuthCookieFromResp(resp, conf.ForwardAuth.CookieName); cookie != nil {
		t.Errorf("refresh must not re-issue the session cookie, got %+v", cookie)
	}

	session, err := h.db.ProxySessions.SelectById(sessionID)
	if err != nil || session == nil {
		t.Fatalf("select session after refresh: row=%v err=%v", session, err)
	}
	if session.AccessToken != newAccess {
		t.Errorf("stored access token not updated: got %q, want %q", session.AccessToken, newAccess)
	}
	if session.AccessExp <= now {
		t.Errorf("stored access expiry not advanced: %d", session.AccessExp)
	}
	if session.RefreshToken == refreshToken {
		t.Error("stored refresh token must be rotated")
	}
	if old, err := h.db.RefreshTokens.SelectByToken(refreshToken); err != nil || old != nil {
		t.Errorf("old refresh token must be deleted (row=%v err=%v)", old, err)
	}

	// The same cookie keeps working without another refresh.
	resp = forwardAuthRequest(t, srv.URL, conf.ForwardAuth.CookieName, sessionID)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("second auth = %d, want 202", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Auth-Request-Access-Token"); got != newAccess {
		t.Errorf("second auth token = %q, want the refreshed token %q", got, newAccess)
	}
}

// Concurrent subrequests on an expired session must refresh exactly once and
// reuse the refreshed token, never double-rotate the refresh token chain.
func TestForwardAuthAuthConcurrentRefreshSingleRotation(t *testing.T) {
	h, conf := newForwardAuthTestHandler(t)
	_, user := seedClientAndUser(t, h)
	proxy, err := h.db.Clients.SelectByClientId("proxy")
	if err != nil || proxy == nil {
		t.Fatalf("select proxy client: %v", err)
	}
	oldAccess, _, err := h.issueAccessToken(user, proxy, "openid profile")
	if err != nil {
		t.Fatal(err)
	}
	refreshToken, err := h.sv.GenAndInsertRefreshToken(proxy, user, "openid profile")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	sessionID := seedProxySession(t, h, user, oldAccess, refreshToken, now-10, now+86400)

	srv := httptest.NewServer(h.router())
	defer srv.Close()

	const workers = 8
	start := make(chan struct{})
	var wg sync.WaitGroup
	tokens := make([]string, workers)
	codes := make([]int, workers)
	errs := make([]error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			resp, err := forwardAuthRequestE(srv.URL, conf.ForwardAuth.CookieName, sessionID)
			if err != nil {
				errs[i] = err
				return
			}
			defer func() { _ = resp.Body.Close() }()
			codes[i] = resp.StatusCode
			tokens[i] = resp.Header.Get("X-Auth-Request-Access-Token")
		}(i)
	}
	close(start)
	wg.Wait()

	for i := 0; i < workers; i++ {
		if errs[i] != nil {
			t.Fatalf("worker %d request error: %v", i, errs[i])
		}
		if codes[i] != http.StatusAccepted {
			t.Fatalf("worker %d status = %d, want 202", i, codes[i])
		}
		if tokens[i] == "" || tokens[i] == oldAccess {
			t.Fatalf("worker %d token = %q, want a refreshed token", i, tokens[i])
		}
		if tokens[i] != tokens[0] {
			t.Fatalf("worker %d token %q differs from %q (double rotation)", i, tokens[i], tokens[0])
		}
	}

	// Exactly one rotation leaves exactly one live refresh token for the client.
	remaining, err := h.db.RefreshTokens.SelectByToken(refreshToken)
	if err != nil || remaining != nil {
		t.Fatalf("old refresh token must be gone (row=%v err=%v)", remaining, err)
	}
}

func TestForwardAuthSignOutDeletesSessionAndRevokes(t *testing.T) {
	h, conf := newForwardAuthTestHandler(t)
	_, user := seedClientAndUser(t, h)
	proxy, err := h.db.Clients.SelectByClientId("proxy")
	if err != nil || proxy == nil {
		t.Fatalf("select proxy client: %v", err)
	}
	accessToken, _, err := h.issueAccessToken(user, proxy, "openid profile")
	if err != nil {
		t.Fatal(err)
	}
	refreshToken, err := h.sv.GenAndInsertRefreshToken(proxy, user, "openid profile")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	sessionID := seedProxySession(t, h, user, accessToken, refreshToken, now+3600, now+86400)

	srv := httptest.NewServer(h.router())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/oauth2/sign_out?rd=/bye", nil)
	req.AddCookie(&http.Cookie{Name: conf.ForwardAuth.CookieName, Value: sessionID})
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("sign_out status = %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/bye" {
		t.Fatalf("sign_out location = %q, want /bye", loc)
	}
	cleared := forwardAuthCookieFromResp(resp, conf.ForwardAuth.CookieName)
	if cleared == nil || cleared.MaxAge >= 0 {
		t.Fatal("sign_out must clear the session cookie")
	}
	if row, err := h.db.ProxySessions.SelectById(sessionID); err != nil || row != nil {
		t.Fatalf("sign_out must delete the session row (row=%v err=%v)", row, err)
	}
	if rt, err := h.db.RefreshTokens.SelectByToken(refreshToken); err != nil || rt != nil {
		t.Fatalf("sign_out must revoke the refresh token (row=%v err=%v)", rt, err)
	}
	if code := userinfoStatus(t, srv.URL, accessToken); code != http.StatusUnauthorized {
		t.Fatalf("access token after sign_out = %d, want 401", code)
	}

	// The old cookie now yields 401.
	resp = forwardAuthRequest(t, srv.URL, conf.ForwardAuth.CookieName, sessionID)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("auth after sign_out = %d, want 401", resp.StatusCode)
	}
}

func TestForwardAuthDisabledRoutesReturnJSON404(t *testing.T) {
	h, _ := newTestHandler(t)
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	for _, path := range []string{"/oauth2", "/oauth2/whatever", "/oauth2/start", "/oauth2/auth"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body := map[string]any{}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s = %d, want 404", path, resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
			t.Errorf("%s content-type = %q, want JSON", path, ct)
		}
		if body["ok"] != false {
			t.Errorf("%s body = %v, want ok=false", path, body)
		}
	}

	// Existing endpoints are unaffected when forward auth is disabled.
	resp, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health = %d, want 200", resp.StatusCode)
	}
}

// FIX F: the bare /oauth2 path must be a JSON 404, not a 307 to /oauth2/.
func TestForwardAuthBareOAuth2JSON404(t *testing.T) {
	h, _ := newForwardAuthTestHandler(t)
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	client := noRedirectClient()
	resp, err := client.Get(srv.URL + "/oauth2")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("/oauth2 = %d, want 404 (no redirect)", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		t.Fatalf("/oauth2 redirected to %q, want JSON 404", loc)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("/oauth2 content-type = %q, want JSON", ct)
	}
}

// FIX B: registration rejects usernames with control characters.
func TestRegisterRejectsControlCharUsername(t *testing.T) {
	h, _ := newTestHandler(t)
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	for _, username := range []string{"al\x01ice", "ali\rce", "ali\nce", "ali\x7fce"} {
		body := fmt.Sprintf(`{"username":%q,"password":"password123","invitationCode":"test-invite"}`, username)
		resp, err := http.Post(srv.URL+"/setup/register", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]any{}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		_ = resp.Body.Close()
		if out["ok"] != false {
			t.Fatalf("register %q body = %v, want ok=false", username, out)
		}
		if user, err := h.db.Users.SelectByName(username); err != nil || user != nil {
			t.Fatalf("control-char username %q was registered (user=%v err=%v)", username, user, err)
		}
	}
	// A clean username still registers.
	body := `{"username":"bob","password":"password123","invitationCode":"test-invite"}`
	resp, err := http.Post(srv.URL+"/setup/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if user, err := h.db.Users.SelectByName("bob"); err != nil || user == nil {
		t.Fatalf("clean username was not registered (user=%v err=%v)", user, err)
	}
}
