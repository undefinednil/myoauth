package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// A refresh token must rotate exactly once. Presenting the same token twice is
// a replay: the second request gets invalid_grant and the whole user/client
// chain is revoked, so the token minted by the first rotation stops working.
func TestRefreshTokenReplayRevokesChain(t *testing.T) {
	h, _ := newTestHandler(t)
	client, user := seedClientAndUser(t, h)
	refreshToken, err := h.sv.GenAndInsertRefreshToken(t.Context(), client, user, "openid profile")
	if err != nil {
		t.Fatalf("insert refresh: %v", err)
	}
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	// First rotation succeeds and returns a successor token.
	status, body := postForm(t, srv.URL+"/token", testClientId, testClientSecret, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	})
	if status != http.StatusOK {
		t.Fatalf("first refresh = %d %v, want 200", status, body)
	}
	rotated, _ := body["refresh_token"].(string)
	if rotated == "" || rotated == refreshToken {
		t.Fatalf("first refresh must rotate the token, got %q", rotated)
	}

	// Replaying the consumed token fails with invalid_grant...
	status, body = postForm(t, srv.URL+"/token", testClientId, testClientSecret, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	})
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("replayed refresh = %d %v, want 400 invalid_grant", status, body)
	}

	// ...and revokes the chain: the successor row is gone and unusable.
	if row, err := h.db.RefreshTokens.SelectByToken(t.Context(), rotated); err != nil || row != nil {
		t.Fatalf("replay must revoke the rotated token (row=%v err=%v)", row, err)
	}
	status, body = postForm(t, srv.URL+"/token", testClientId, testClientSecret, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rotated},
	})
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("successor after replay = %d %v, want 400 invalid_grant", status, body)
	}
}

// /authorize rejects scopes outside the provider's allowlist with the exact
// redirect-error semantics, while the openid-required check keeps its original
// invalid_scope behavior and ordering.
func TestAuthorizeRejectsUnsupportedScope(t *testing.T) {
	h, _ := newTestHandler(t)
	seedClientAndUser(t, h)
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	newQuery := func(scope string) url.Values {
		return url.Values{
			"response_type":         {"code"},
			"client_id":             {testClientId},
			"redirect_uri":          {testRedirectURI},
			"scope":                 {scope},
			"state":                 {"st-1"},
			"code_challenge":        {challengeOf(strings.Repeat("a", 48))},
			"code_challenge_method": {"S256"},
		}
	}
	redirectError := func(t *testing.T, query url.Values) (string, string) {
		t.Helper()
		resp, err := noRedirectClient().Get(srv.URL + "/authorize?" + query.Encode())
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("authorize status = %d, want 302", resp.StatusCode)
		}
		loc, err := url.Parse(resp.Header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		if got := loc.Scheme + "://" + loc.Host + loc.Path; got != testRedirectURI {
			t.Fatalf("error redirect = %q, want %q", got, testRedirectURI)
		}
		if got := loc.Query().Get("state"); got != "st-1" {
			t.Fatalf("error redirect state = %q, want st-1", got)
		}
		if desc := loc.Query().Get("error_description"); desc == "" {
			t.Fatal("error redirect must carry an error_description")
		}
		return loc.Query().Get("error"), loc.Query().Get("error_description")
	}

	// A supported set containing openid is fine and reaches the login redirect.
	resp, err := noRedirectClient().Get(srv.URL + "/authorize?" + newQuery("openid profile").Encode())
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") == "" {
		t.Fatalf("supported scope status = %d, want a 302 redirect", resp.StatusCode)
	}

	// openid present but an unsupported scope requested -> unsupported_scope.
	code, desc := redirectError(t, newQuery("openid admin"))
	if code != "unsupported_scope" {
		t.Fatalf("unsupported scope error = %q (%s), want unsupported_scope", code, desc)
	}

	// Missing openid keeps the original invalid_scope behavior, even when the
	// requested scope is also unsupported: the openid check runs first.
	code, _ = redirectError(t, newQuery("admin"))
	if code != "invalid_scope" {
		t.Fatalf("missing openid error = %q, want invalid_scope", code)
	}
}

// /userinfo must reject an access token whose audience is not a client that
// exists in the DB, even though the token is otherwise validly signed.
func TestUserinfoRejectsDeletedClientAudience(t *testing.T) {
	h, _ := newTestHandler(t)
	client, user := seedClientAndUser(t, h)
	accessToken, _, err := h.issueAccessToken(t.Context(), user, client, "openid")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h.router())
	defer srv.Close()

	// The token is accepted while its audience client still exists...
	if code := userinfoStatus(t, srv.URL, accessToken); code != http.StatusOK {
		t.Fatalf("userinfo with a live audience client = %d, want 200", code)
	}
	// ...and rejected once that client is gone.
	if err := h.db.Clients.DeleteById(t.Context(), client.Id); err != nil {
		t.Fatal(err)
	}
	if code := userinfoStatus(t, srv.URL, accessToken); code != http.StatusUnauthorized {
		t.Fatalf("userinfo after client deletion = %d, want 401", code)
	}
}
