package handler

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/undefinednil/myoauth/token"
	"github.com/undefinednil/myoauth/web"
)

// adminCall drives an admin endpoint with the given method. Cookies and the
// CSRF header are only attached when non-empty, so the same helper can test the
// unauthenticated and CSRF-rejected paths. The body is returned raw so callers
// can assert on the exact JSON shape (e.g. that no secret field is present).
func adminCall(t *testing.T, method, endpoint, session, csrf, body string) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, endpoint, reader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if session != "" {
		req.AddCookie(&http.Cookie{Name: adminCookieName, Value: session})
	}
	if csrf != "" {
		req.AddCookie(&http.Cookie{Name: adminCSRFCookieName, Value: csrf})
		req.Header.Set("X-CSRF-Token", csrf)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

// adminLoginAndCookies signs in over HTTP (the real flow, not a minted session)
// and returns the session id and CSRF token from the response cookies.
func adminLoginAndCookies(t *testing.T, srvURL string) (string, string) {
	t.Helper()
	resp, err := http.Post(srvURL+"/setup/admin-login", "application/json", strings.NewReader(fmt.Sprintf(`{"adminPassword":%q}`, testAdminPassword)))
	if err != nil {
		t.Fatalf("admin login: %v", err)
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
	return session, csrf
}

// TestJWKSEndpoint fetches the published key set, reconstructs the RSA public
// key, checks the metadata a verifier relies on (kid/alg/use), and verifies a
// freshly issued ID token's signature with that reconstructed key. It also
// checks the kid in the JWT header matches the JWKS kid.
func TestJWKSEndpoint(t *testing.T) {
	h, _ := newTestHandler(t)
	client, user := seedClientAndUser(t, h)
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("get jwks: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("jwks status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Cache-Control"); got != "public, max-age=86400" {
		t.Errorf("jwks Cache-Control = %q, want public, max-age=86400", got)
	}

	var jwks struct {
		Keys []token.Jwk `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("jwks keys = %d, want exactly 1", len(jwks.Keys))
	}
	key := jwks.Keys[0]
	if key.Kty != "RSA" || key.Use != "sig" || key.Alg != "RS256" {
		t.Fatalf("unexpected key metadata: %+v", key)
	}
	if key.Kid == "" || key.N == "" || key.E == "" {
		t.Fatalf("key is missing kid/n/e: %+v", key)
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		t.Fatalf("decode modulus: %v", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		t.Fatalf("decode exponent: %v", err)
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(new(big.Int).SetBytes(eBytes).Int64())}
	if pub.E != 65537 {
		t.Errorf("key exponent = %d, want 65537", pub.E)
	}
	if pub.N.BitLen() != 2048 {
		t.Errorf("key size = %d bits, want 2048", pub.N.BitLen())
	}

	accessToken, _, err := h.issueAccessToken(t.Context(), user, client, "openid")
	if err != nil {
		t.Fatalf("issue access token: %v", err)
	}
	idToken, err := h.issueIDToken(user, client, "", accessToken, "", time.Now())
	if err != nil {
		t.Fatalf("issue id token: %v", err)
	}
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		t.Fatalf("id token is not a JWT: %q", idToken)
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	if header.Alg != "RS256" {
		t.Errorf("jwt alg = %q, want RS256", header.Alg)
	}
	if header.Kid != key.Kid {
		t.Errorf("jwt kid = %q, want jwks kid %q", header.Kid, key.Kid)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("id token signature does not verify with the JWKS key: %v", err)
	}
}

// TestSPAFallbackAndAsset404 checks the catch-all route: a client-side route
// without an extension is served the SPA shell (when the frontend has been
// built into web/dist) or the helpful "frontend not built" 503, while a missing
// asset-looking path is a real 404 and never falls back to HTML.
func TestSPAFallbackAndAsset404(t *testing.T) {
	h, _ := newTestHandler(t)
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/console/client/some-route")
	if err != nil {
		t.Fatalf("get spa route: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)

	if _, indexErr := fs.ReadFile(web.FS, "dist/index.html"); indexErr == nil {
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("spa route status = %d, want 200 (body %q)", resp.StatusCode, body)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("spa route Content-Type = %q, want text/html", ct)
		}
		if !strings.Contains(string(body), `id="root"`) {
			t.Errorf("spa fallback did not serve index.html: %q", body)
		}
	} else {
		// web/dist is gitignored, so CI runs the suite before the frontend is
		// built; the handler must then answer 503 with the build hint.
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("unbuilt spa route status = %d, want 503 (body %q)", resp.StatusCode, body)
		}
		if !strings.Contains(string(body), "Frontend not built") {
			t.Errorf("unbuilt spa fallback body = %q, want the build hint", body)
		}
	}

	assetResp, err := http.Get(srv.URL + "/assets/does-not-exist-0123456789.js")
	if err != nil {
		t.Fatalf("get missing asset: %v", err)
	}
	defer func() { _ = assetResp.Body.Close() }()
	if assetResp.StatusCode != http.StatusNotFound {
		t.Fatalf("missing asset status = %d, want 404", assetResp.StatusCode)
	}
}

// TestAdminClientCRUDAndLogout is the admin console round trip: login, list
// (unauthorized without a session), create, list, update, delete, and finally
// logout, after which the very same session cookie must be rejected because the
// server-side entry is gone.
func TestAdminClientCRUDAndLogout(t *testing.T) {
	h, _ := newTestHandler(t)
	seedClientAndUser(t, h)
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	// No session: the list endpoint must not disclose anything.
	if status, _ := adminCall(t, http.MethodGet, srv.URL+"/setup/client-list", "", "", ""); status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated client-list status = %d, want 401", status)
	}

	session, csrf := adminLoginAndCookies(t, srv.URL)

	createBody := `{"clientId":"crud-client","secret":"crud-secret","redirects":"https://crud.example.com/a","accessTokenAge":1,"refreshTokenAge":24}`
	if status, body := adminCall(t, http.MethodPost, srv.URL+"/setup/client-create", session, csrf, createBody); status != http.StatusOK {
		t.Fatalf("client-create status = %d, body = %s", status, body)
	}

	listClients := func() []map[string]any {
		t.Helper()
		status, body := adminCall(t, http.MethodGet, srv.URL+"/setup/client-list", session, csrf, "")
		if status != http.StatusOK {
			t.Fatalf("client-list status = %d, body = %s", status, body)
		}
		var decoded struct {
			Ok      bool             `json:"ok"`
			Clients []map[string]any `json:"clients"`
		}
		if err := json.Unmarshal(body, &decoded); err != nil {
			t.Fatalf("decode client-list: %v (body %s)", err, body)
		}
		if !decoded.Ok {
			t.Fatalf("client-list ok = false: %s", body)
		}
		return decoded.Clients
	}
	findClient := func(clients []map[string]any) map[string]any {
		t.Helper()
		for _, entry := range clients {
			if entry["clientId"] == "crud-client" {
				if _, leaks := entry["secret"]; leaks {
					t.Fatal("client-list must not expose the secret")
				}
				return entry
			}
		}
		t.Fatalf("crud-client not present in client-list: %v", clients)
		return nil
	}

	entry := findClient(listClients())
	createdID := int64(entry["id"].(float64))
	if entry["redirects"] != "https://crud.example.com/a" {
		t.Fatalf("created redirects = %v, want https://crud.example.com/a", entry["redirects"])
	}
	before, err := h.db.Clients.SelectById(t.Context(), createdID)
	if err != nil || before == nil {
		t.Fatalf("select created client: %v %+v", err, before)
	}

	updateBody := fmt.Sprintf(`{"id":%d,"clientId":"crud-client","redirects":"https://crud.example.com/b","accessTokenAge":2,"refreshTokenAge":48}`, createdID)
	if status, body := adminCall(t, http.MethodPost, srv.URL+"/setup/client-update", session, csrf, updateBody); status != http.StatusOK {
		t.Fatalf("client-update status = %d, body = %s", status, body)
	}
	after, err := h.db.Clients.SelectById(t.Context(), createdID)
	if err != nil || after == nil {
		t.Fatalf("select updated client: %v %+v", err, after)
	}
	if after.Redirects != "https://crud.example.com/b" || after.AccessTokenAge != 2 || after.RefreshTokenAge != 48 {
		t.Fatalf("update did not persist: %+v", after)
	}
	// An empty secret in the update must keep the stored hash.
	if after.Secret != before.Secret {
		t.Fatal("client-update with an empty secret must preserve the existing hash")
	}
	entry = findClient(listClients())
	if entry["redirects"] != "https://crud.example.com/b" {
		t.Fatalf("client-list after update = %v, want the new redirects", entry["redirects"])
	}

	if status, body := adminCall(t, http.MethodDelete, srv.URL+"/setup/client-delete", session, csrf, fmt.Sprintf(`{"id":%d}`, createdID)); status != http.StatusOK {
		t.Fatalf("client-delete status = %d, body = %s", status, body)
	}
	deleted, err := h.db.Clients.SelectById(t.Context(), createdID)
	if err != nil {
		t.Fatalf("select deleted client: %v", err)
	}
	if deleted != nil {
		t.Fatalf("client still visible after delete: %+v", deleted)
	}
	for _, entry := range listClients() {
		if entry["clientId"] == "crud-client" {
			t.Fatal("deleted client still returned by client-list")
		}
	}

	if status, body := adminCall(t, http.MethodPost, srv.URL+"/setup/admin-logout", session, csrf, `{}`); status != http.StatusOK {
		t.Fatalf("admin-logout status = %d, body = %s", status, body)
	}
	if status, _ := adminCall(t, http.MethodGet, srv.URL+"/setup/client-list", session, csrf, ""); status != http.StatusUnauthorized {
		t.Fatalf("client-list after logout status = %d, want 401", status)
	}
}

// TestResponseInternalError checks the shared 500 helper: the response must be
// the generic body (never the underlying error, which is only logged).
func TestResponseInternalError(t *testing.T) {
	rec := httptest.NewRecorder()
	responseInternalError(rec, log.New(io.Discard, "", 0), errors.New("boom"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["ok"] != false || body["msg"] != "internal error" {
		t.Fatalf("body = %v, want the generic internal error", body)
	}
	if strings.Contains(rec.Body.String(), "boom") {
		t.Fatal("response must not leak the underlying error")
	}
}

// TestDeletedClientIsRejected checks that deleting a client invalidates every
// path keyed on it: the client can no longer authenticate (/introspect,
// /token), and an access token minted for it is rejected by /userinfo because
// its audience no longer resolves to a registered client.
func TestDeletedClientIsRejected(t *testing.T) {
	h, _ := newTestHandler(t)
	_, user := seedClientAndUser(t, h)
	second := seedSecondClient(t, h)
	accessToken, _, err := h.issueAccessToken(t.Context(), user, second, "openid")
	if err != nil {
		t.Fatalf("issue access token: %v", err)
	}
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	session, csrf := adminSessionForTest(t, h)
	if status, body := adminCall(t, http.MethodDelete, srv.URL+"/setup/client-delete", session, csrf, fmt.Sprintf(`{"id":%d}`, second.Id)); status != http.StatusOK {
		t.Fatalf("client-delete status = %d (body %s), want 200", status, body)
	}

	// The deleted client's credentials are rejected outright.
	if status, body := postForm(t, srv.URL+"/introspect", "client-2", "secret-2", url.Values{"token": {accessToken}}); status != http.StatusUnauthorized {
		t.Fatalf("deleted client introspect status = %d (body %v), want 401", status, body)
	}
	if status, body := postForm(t, srv.URL+"/token", "client-2", "secret-2", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"whatever"},
	}); status != http.StatusUnauthorized {
		t.Fatalf("deleted client token status = %d (body %v), want 401", status, body)
	}
	// Its still-signed access token must fail the audience check at /userinfo.
	if code := userinfoStatus(t, srv.URL, accessToken); code != http.StatusUnauthorized {
		t.Fatalf("userinfo with deleted-client token = %d, want 401", code)
	}
}
