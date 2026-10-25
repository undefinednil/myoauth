package handler

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/zenpk/my-oauth/dal"
	"github.com/zenpk/my-oauth/util"
)

// The forward-auth service is an OIDC Relying Party of this same provider. nginx
// uses it as an `auth_request` backend to gate a protected location and to learn
// the authenticated identity via response headers. It replaces oauth2-proxy.
//
// Sessions are kept server-side (SQLite): the browser cookie only carries an
// opaque random session id. This is required because nginx's `auth_request`
// never forwards `Set-Cookie` from the subrequest, so a token rotation during a
// refresh cannot be communicated back to the browser. With server-side sessions
// the subrequest updates the stored tokens in place and the same cookie keeps
// working (FIX A).
const (
	forwardAuthStateCookieTTL  = 10 * time.Minute
	forwardAuthAccessTokenAge  = 1   // hours, used when auto-creating the proxy client
	forwardAuthRefreshTokenAge = 720 // hours (30 days), used when auto-creating the proxy client
	forwardAuthSessionIDBytes  = 32  // opaque session id entropy
)

// forwardAuthState is the short-lived payload persisted between the login
// redirect and the callback (encrypted, HttpOnly). It is the only value that
// still uses util.SecureCookieCodec.
type forwardAuthState struct {
	State        string `json:"state"`
	CodeVerifier string `json:"codeVerifier"`
	Rd           string `json:"rd"`
}

// forwardAuthSessionLock serialises concurrent auth subrequests that share a
// session id so at most one of them refreshes a rotated token while the others
// reuse the refreshed result.
type forwardAuthSessionLock struct {
	mu   sync.Mutex
	refs int
}

// forwardAuthSessions owns the per-session locks. It is heap-allocated once and
// referenced by the Handler so every request handler copy shares the same locks
// and map.
type forwardAuthSessions struct {
	mu    sync.Mutex
	locks map[string]*forwardAuthSessionLock
}

func newForwardAuthSessions() *forwardAuthSessions {
	return &forwardAuthSessions{locks: make(map[string]*forwardAuthSessionLock)}
}

// acquire returns the lock for sessionID, creating it on demand, and increments
// its reference count so opportunistic cleanup cannot drop a lock still in use.
func (s *forwardAuthSessions) acquire(sessionID string) *forwardAuthSessionLock {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, ok := s.locks[sessionID]
	if !ok {
		lock = &forwardAuthSessionLock{}
		s.locks[sessionID] = lock
	}
	lock.refs++
	return lock
}

// release unlocks the session lock and removes it from the map once no other
// goroutine references it, keeping the map bounded.
func (s *forwardAuthSessions) release(sessionID string, lock *forwardAuthSessionLock) {
	lock.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	lock.refs--
	if lock.refs <= 0 {
		if current, ok := s.locks[sessionID]; ok && current == lock {
			delete(s.locks, sessionID)
		}
	}
}

// EnsureForwardAuthClient creates the proxy's OIDC client on startup if it does
// not exist yet, so the flow works without manual admin setup. It never
// overwrites an existing client.
func (h *Handler) EnsureForwardAuthClient() error {
	fa := h.conf.ForwardAuth
	if fa == nil || !fa.Enabled {
		return nil
	}
	existing, err := h.db.Clients.SelectByClientId(fa.ClientId)
	if err != nil {
		return err
	}
	if existing != nil {
		h.logger.Printf("forward auth: client %q already exists (id=%d), leaving it unchanged\n", fa.ClientId, existing.Id)
		return nil
	}
	hashed, err := util.BCryptPassword(fa.ClientSecret)
	if err != nil {
		return err
	}
	client := &dal.Client{
		ClientId:        fa.ClientId,
		Secret:          hashed,
		Redirects:       h.forwardAuthRedirectURI(),
		AccessTokenAge:  forwardAuthAccessTokenAge,
		RefreshTokenAge: forwardAuthRefreshTokenAge,
	}
	if err := h.db.Clients.Insert(client); err != nil {
		return err
	}
	h.logger.Printf("forward auth: created client %q with redirect_uri %q\n", client.ClientId, client.Redirects)
	return nil
}

// forwardAuthLogin starts the login flow: it validates the return URL, mints
// state + PKCE, stashes them in an encrypted cookie and redirects to /authorize.
func (h Handler) forwardAuthLogin(w http.ResponseWriter, r *http.Request) {
	fa := h.conf.ForwardAuth

	rd := h.safeReturnURL(r.URL.Query().Get("rd"))

	state, err := util.RandString(32)
	if err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
	codeVerifier, err := util.RandString(64)
	if err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
	sum := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(sum[:])

	encodedState, err := h.faCodec.Encode(forwardAuthState{State: state, CodeVerifier: codeVerifier, Rd: rd})
	if err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
	h.setForwardAuthCookie(w, h.forwardAuthStateCookieName(), encodedState, int(forwardAuthStateCookieTTL.Seconds()))

	authorize, err := url.Parse(h.oidcIssuer() + "/authorize")
	if err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
	query := authorize.Query()
	query.Set("client_id", fa.ClientId)
	query.Set("redirect_uri", h.forwardAuthRedirectURI())
	query.Set("response_type", "code")
	query.Set("scope", "openid profile")
	query.Set("state", state)
	query.Set("code_challenge", codeChallenge)
	query.Set("code_challenge_method", "S256")
	authorize.RawQuery = query.Encode()
	http.Redirect(w, r, authorize.String(), http.StatusFound)
}

// forwardAuthCallback validates state, exchanges the code server-side, verifies
// the ID token, persists a server-side session and sets the opaque session id
// cookie.
func (h Handler) forwardAuthCallback(w http.ResponseWriter, r *http.Request) {
	fa := h.conf.ForwardAuth
	query := r.URL.Query()
	code := query.Get("code")
	state := query.Get("state")

	stateCookie, err := r.Cookie(h.forwardAuthStateCookieName())
	if err != nil || stateCookie.Value == "" {
		responseOIDCError(w, http.StatusBadRequest, "invalid_request", "missing state cookie")
		return
	}
	var st forwardAuthState
	if err := h.faCodec.Decode(stateCookie.Value, &st); err != nil {
		h.clearForwardAuthCookie(w, h.forwardAuthStateCookieName())
		responseOIDCError(w, http.StatusBadRequest, "invalid_request", "invalid state cookie")
		return
	}
	// The state cookie is single-use regardless of the outcome below.
	h.clearForwardAuthCookie(w, h.forwardAuthStateCookieName())

	if subtle.ConstantTimeCompare([]byte(st.State), []byte(state)) != 1 {
		responseOIDCError(w, http.StatusBadRequest, "invalid_request", "state mismatch")
		return
	}

	client, err := h.db.Clients.SelectByClientId(fa.ClientId)
	if err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
	if client == nil {
		responseOIDCError(w, http.StatusInternalServerError, "server_error", "proxy client is not configured")
		return
	}

	resp, _, err := h.exchangeAuthorizationCode(client, code, st.CodeVerifier, h.forwardAuthRedirectURI())
	if err != nil {
		h.respondTokenExchangeError(w, err)
		return
	}

	claims, ok, err := h.tk.ParseAndVerifyIDJwt(resp.IDToken, fa.ClientId)
	if err != nil || !ok {
		responseOIDCError(w, http.StatusBadRequest, "invalid_request", "invalid id_token")
		return
	}

	sessionID, err := util.RandBase64URL(forwardAuthSessionIDBytes)
	if err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
	now := time.Now()
	ttl := h.forwardAuthSessionTTL(client)
	session := &dal.ProxySession{
		Id:           sessionID,
		UserUuid:     claims.Subject,
		Name:         forwardAuthIDTokenName(resp.IDToken),
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		AccessExp:    now.Add(time.Duration(resp.ExpiresIn) * time.Second).Unix(),
		Exp:          now.Add(ttl).Unix(),
		CreatedAt:    now.Unix(),
	}
	if err := h.db.ProxySessions.Insert(session); err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
	h.setForwardAuthSession(w, sessionID, session.Exp)
	http.Redirect(w, r, st.Rd, http.StatusFound)
}

// forwardAuthAuth is the `auth_request` subrequest target. It answers 202 with
// the identity headers on success and 401 otherwise, never a body or redirect
// that nginx could proxy to the client.
func (h Handler) forwardAuthAuth(w http.ResponseWriter, r *http.Request) {
	fa := h.conf.ForwardAuth
	cookie, err := r.Cookie(fa.CookieName)
	if err != nil || cookie.Value == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	sessionID := cookie.Value

	// Serialise subrequests for the same session so concurrent expiries trigger
	// exactly one refresh/rotation; later requests re-read the updated row.
	sessionLock := h.faSessions.acquire(sessionID)
	sessionLock.mu.Lock()
	defer h.faSessions.release(sessionID, sessionLock)

	session, err := h.db.ProxySessions.SelectById(sessionID)
	if err != nil {
		h.logger.Println("internal error:", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	now := time.Now().Unix()
	if session == nil || session.Exp <= now {
		if session != nil {
			_ = h.db.ProxySessions.DeleteById(sessionID)
		}
		h.clearForwardAuthSession(w)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if session.AccessExp <= now {
		// FIX C: an expired access token with no way to refresh must deny, never
		// 202 with a dead token.
		if session.RefreshToken == "" {
			_ = h.db.ProxySessions.DeleteById(sessionID)
			h.clearForwardAuthSession(w)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		client, err := h.db.Clients.SelectByClientId(fa.ClientId)
		if err != nil || client == nil {
			_ = h.db.ProxySessions.DeleteById(sessionID)
			h.clearForwardAuthSession(w)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		resp, _, err := h.exchangeRefreshToken(client, session.RefreshToken, "")
		if err != nil {
			_ = h.db.ProxySessions.DeleteById(sessionID)
			h.clearForwardAuthSession(w)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		session.AccessToken = resp.AccessToken
		if resp.RefreshToken != "" {
			session.RefreshToken = resp.RefreshToken
		}
		session.AccessExp = now + resp.ExpiresIn
		if err := h.db.ProxySessions.UpdateById(session); err != nil {
			h.logger.Println("internal error:", err)
			_ = h.db.ProxySessions.DeleteById(sessionID)
			h.clearForwardAuthSession(w)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}

	// Header values are sanitized as defense in depth so a stored name can never
	// inject a header (FIX B). Upstreams must authorize on the immutable UUID in
	// X-Auth-Request-User, never on the preferred-username header.
	w.Header().Set("X-Auth-Request-User", sanitizeAuthHeader(session.UserUuid))
	w.Header().Set("X-Auth-Request-Preferred-Username", sanitizeAuthHeader(session.Name))
	w.Header().Set("X-Auth-Request-Access-Token", sanitizeAuthHeader(session.AccessToken))
	w.WriteHeader(http.StatusAccepted)
}

// forwardAuthSignOut deletes the server-side session (and best-effort revokes
// its refresh + outstanding access tokens) before redirecting to a validated
// return URL.
func (h Handler) forwardAuthSignOut(w http.ResponseWriter, r *http.Request) {
	fa := h.conf.ForwardAuth
	if cookie, err := r.Cookie(fa.CookieName); err == nil && cookie.Value != "" {
		sessionID := cookie.Value
		sessionLock := h.faSessions.acquire(sessionID)
		sessionLock.mu.Lock()
		if session, err := h.db.ProxySessions.SelectById(sessionID); err == nil && session != nil {
			_ = h.db.ProxySessions.DeleteById(sessionID)
			if user, err := h.db.Users.SelectByUuid(session.UserUuid); err == nil && user != nil {
				if client, err := h.db.Clients.SelectByClientId(fa.ClientId); err == nil && client != nil {
					_ = h.sv.RevokeUserSessions(user.Id, client.Id)
					_ = h.db.TokenStore.RevokeAccessTokensByUserAndClient(user.Id, client.Id)
				}
			}
		}
		h.faSessions.release(sessionID, sessionLock)
	}
	h.clearForwardAuthSession(w)
	http.Redirect(w, r, h.safeReturnURL(r.URL.Query().Get("rd")), http.StatusFound)
}

// sanitizeAuthHeader strips control characters (including CR/LF) so a stored
// value can never break out of a response header.
func sanitizeAuthHeader(value string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
}

func (h Handler) forwardAuthRedirectURI() string {
	return h.oidcIssuer() + h.conf.ForwardAuth.CallbackPath
}

func (h Handler) forwardAuthStateCookieName() string {
	return h.conf.ForwardAuth.CookieName + "_state"
}

func (h Handler) forwardAuthSessionTTL(client *dal.Client) time.Duration {
	if h.conf.ForwardAuth.SessionTtlSeconds > 0 {
		return time.Duration(h.conf.ForwardAuth.SessionTtlSeconds) * time.Second
	}
	return time.Duration(client.RefreshTokenAge) * time.Hour
}

// safeReturnURL validates the `rd` parameter against open redirects: it accepts
// a scheme-less relative path (not "//host") or an absolute URL whose host is
// on allowedRedirectDomains, and falls back to "/" otherwise.
func (h Handler) safeReturnURL(rd string) string {
	rd = strings.TrimSpace(rd)
	if rd == "" {
		return "/"
	}
	if isRelativeReturnPath(rd) {
		return rd
	}
	u, err := url.Parse(rd)
	if err != nil {
		return "/"
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "/"
	}
	if h.forwardAuthHostAllowed(u) {
		return rd
	}
	return "/"
}

func isRelativeReturnPath(rd string) bool {
	if !strings.HasPrefix(rd, "/") {
		return false
	}
	if strings.HasPrefix(rd, "//") {
		return false
	}
	if strings.Contains(rd, "\\") {
		return false
	}
	// Reject any control character (CR, LF, TAB, NUL, ...).
	for _, r := range rd {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	// Reject percent-encoded path separators, which some upstreams/parsers
	// normalize to "/" or "\" and could turn a relative path into an authority.
	lower := strings.ToLower(rd)
	if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
		return false
	}
	return true
}

// forwardAuthHostAllowed accepts an absolute rd only when its host (and, when
// the allowlist entry names a port, its exact host:port) matches. A bare host
// entry accepts only the scheme's default port, so an attacker cannot smuggle a
// different origin through an arbitrary port (FIX D).
func (h Handler) forwardAuthHostAllowed(u *url.URL) bool {
	// Reject URLs carrying userinfo (https://user:pass@host/) outright.
	if u.User != nil {
		return false
	}
	host := u.Hostname()
	port := u.Port()
	for _, domain := range h.conf.ForwardAuth.AllowedRedirectDomains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}
		if strings.EqualFold(domain, u.Host) {
			return true
		}
		if strings.EqualFold(domain, host) {
			if port == "" ||
				(u.Scheme == "http" && port == "80") ||
				(u.Scheme == "https" && port == "443") {
				return true
			}
		}
	}
	return false
}

// forwardAuthIDTokenName extracts the `name` claim from an already verified ID
// token. The token package's parser does not surface `name`, so the payload is
// decoded again; this is safe because the signature was checked first.
func forwardAuthIDTokenName(idToken string) string {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.Name
}

// setForwardAuthSession writes the opaque session id cookie, whose MaxAge tracks
// the server-side session expiry.
func (h Handler) setForwardAuthSession(w http.ResponseWriter, sessionID string, exp int64) {
	maxAge := int(time.Until(time.Unix(exp, 0)).Seconds())
	if maxAge <= 0 {
		maxAge = 1
	}
	h.setForwardAuthCookie(w, h.conf.ForwardAuth.CookieName, sessionID, maxAge)
}

func (h Handler) clearForwardAuthSession(w http.ResponseWriter) {
	h.clearForwardAuthCookie(w, h.conf.ForwardAuth.CookieName)
}

func (h Handler) setForwardAuthCookie(w http.ResponseWriter, name, value string, maxAge int) {
	fa := h.conf.ForwardAuth
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   fa.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	}
	if fa.CookieDomain != "" {
		cookie.Domain = fa.CookieDomain
	}
	http.SetCookie(w, cookie)
}

func (h Handler) clearForwardAuthCookie(w http.ResponseWriter, name string) {
	h.setForwardAuthCookie(w, name, "", -1)
}
