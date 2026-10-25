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
	// RedirectUri is the exact redirect_uri sent to /authorize; the callback
	// reuses it verbatim so no scheme/host re-derivation can drift.
	RedirectUri string `json:"redirectUri"`
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
// not exist yet, and otherwise makes sure its allowed redirects include the
// callback URI of every effective origin. Manually-added redirects and the
// existing secret/ages are preserved.
func (h *Handler) EnsureForwardAuthClient() error {
	fa := h.conf.ForwardAuth
	if fa == nil || !fa.Enabled {
		return nil
	}
	desired := h.forwardAuthRedirectURIs()
	existing, err := h.db.Clients.SelectByClientId(fa.ClientId)
	if err != nil {
		return err
	}
	if existing != nil {
		merged := mergeForwardAuthRedirects(existing.Redirects, desired)
		if merged == existing.Redirects {
			h.logger.Printf("forward auth: client %q already exists (id=%d) with redirects %q\n", fa.ClientId, existing.Id, existing.Redirects)
			return nil
		}
		// Only the redirects change; the secret and token ages of an existing
		// client are never touched.
		existing.Redirects = merged
		if err := h.db.Clients.UpdateById(existing); err != nil {
			return err
		}
		h.logger.Printf("forward auth: client %q (id=%d) redirects updated to %q\n", fa.ClientId, existing.Id, merged)
		return nil
	}
	hashed, err := util.BCryptPassword(fa.ClientSecret)
	if err != nil {
		return err
	}
	redirects := strings.Join(desired, ",")
	client := &dal.Client{
		ClientId:        fa.ClientId,
		Secret:          hashed,
		Redirects:       redirects,
		AccessTokenAge:  forwardAuthAccessTokenAge,
		RefreshTokenAge: forwardAuthRefreshTokenAge,
	}
	if err := h.db.Clients.Insert(client); err != nil {
		return err
	}
	h.logger.Printf("forward auth: created client %q with redirects %q\n", client.ClientId, redirects)
	return nil
}

// mergeForwardAuthRedirects unions the comma-separated existing redirects with
// the desired ones, preserving first-seen order and dropping duplicates. It
// never removes a redirect that was added manually.
func mergeForwardAuthRedirects(existingCSV string, desired []string) string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(desired)+1)
	add := func(redirect string) {
		redirect = strings.TrimSpace(redirect)
		if redirect == "" {
			return
		}
		if _, ok := seen[redirect]; ok {
			return
		}
		seen[redirect] = struct{}{}
		out = append(out, redirect)
	}
	for _, redirect := range strings.Split(existingCSV, ",") {
		add(redirect)
	}
	for _, redirect := range desired {
		add(redirect)
	}
	return strings.Join(out, ",")
}

// forwardAuthLogin starts the login flow: it derives the requesting origin,
// rejects one that is not on the allowlist, validates the return URL, mints
// state + PKCE, stashes them (including the exact redirect_uri) in an encrypted
// cookie and redirects to /authorize.
//
// Fail-closed: the derived request origin must exactly match an effective
// origin (allowedCallbackOrigins, or the issuer origin when unset). A reverse
// proxy that forwards a Host/X-Forwarded-Host different from oidcIssuer -- and
// without listing that origin in allowedCallbackOrigins -- will therefore get a
// 400 here. That is intentional: configure allowedCallbackOrigins (or align the
// forwarded Host with oidcIssuer) to enable the host-aware flow.
func (h Handler) forwardAuthLogin(w http.ResponseWriter, r *http.Request) {
	fa := h.conf.ForwardAuth

	// The login/callback/session must all live on the protected app's own
	// origin so the session cookie is host-only (and `__Host-` works). A
	// spoofed X-Forwarded-Host can only select another allowlisted origin, so
	// it cannot cause an open redirect.
	origin := h.forwardAuthCanonicalOrigin(forwardAuthRequestOrigin(r))
	if origin == "" {
		responseOIDCError(w, http.StatusBadRequest, "invalid_request", "request origin is not an allowed callback origin")
		return
	}
	redirectURI := h.forwardAuthCallbackURI(origin)

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

	encodedState, err := h.faCodec.Encode(forwardAuthState{State: state, CodeVerifier: codeVerifier, Rd: rd, RedirectUri: redirectURI})
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
	query.Set("redirect_uri", redirectURI)
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

	resp, _, err := h.exchangeAuthorizationCode(client, code, st.CodeVerifier, st.RedirectUri)
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

// effectiveForwardAuthOrigins returns the origins allowed to run the
// forward-auth flow. When allowedCallbackOrigins is configured it wins;
// otherwise the issuer origin is used, preserving the single-host deployment.
func (h Handler) effectiveForwardAuthOrigins() []string {
	fa := h.conf.ForwardAuth
	if fa == nil {
		return nil
	}
	origins := make([]string, 0, len(fa.AllowedCallbackOrigins))
	for _, origin := range fa.AllowedCallbackOrigins {
		if origin = strings.TrimSpace(origin); origin != "" {
			origins = append(origins, origin)
		}
	}
	if len(origins) == 0 {
		return []string{h.oidcIssuer()}
	}
	return origins
}

// forwardAuthRedirectURIs is the callback URI of every effective origin, i.e.
// what must appear on the managed proxy client's allowed redirects.
func (h Handler) forwardAuthRedirectURIs() []string {
	origins := h.effectiveForwardAuthOrigins()
	uris := make([]string, 0, len(origins))
	for _, origin := range origins {
		uris = append(uris, h.forwardAuthCallbackURI(origin))
	}
	return uris
}

// forwardAuthCallbackURI builds the callback redirect_uri for an origin.
func (h Handler) forwardAuthCallbackURI(origin string) string {
	return origin + h.conf.ForwardAuth.CallbackPath
}

// forwardAuthCanonicalOrigin returns the allowlisted origin that matches origin
// case-insensitively, or "" when it is not allowed. Returning the allowlisted
// spelling keeps the redirect_uri byte-identical to the client's registered
// redirect (which /authorize matches exactly).
func (h Handler) forwardAuthCanonicalOrigin(origin string) string {
	origin = strings.TrimSpace(origin)
	if origin == "" {
		return ""
	}
	for _, allowed := range h.effectiveForwardAuthOrigins() {
		if strings.EqualFold(allowed, origin) {
			return allowed
		}
	}
	return ""
}

// forwardAuthRequestOrigin derives the origin (scheme://host) of the incoming
// request. The `/oauth2/*` endpoints only ever run behind the operator's
// reverse proxy, whose config must set X-Forwarded-Host and X-Forwarded-Proto
// (the shipped nginx.forward-auth.example.conf does, pinning both to $host /
// $scheme so a client cannot inject them); the `Host`/`r.TLS` fallbacks exist
// only for direct/local requests. Because the derived origin must exactly match
// an allowlisted origin, a spoofed header cannot create an open redirect.
func forwardAuthRequestOrigin(r *http.Request) string {
	host := firstHeaderValue(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = strings.TrimSpace(r.Host)
	}
	scheme := firstHeaderValue(r.Header.Get("X-Forwarded-Proto"))
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	if host == "" {
		return ""
	}
	return scheme + "://" + host
}

// firstHeaderValue returns the first comma-separated token of a forwarding
// header (or the whole value when there is no comma), trimmed.
func firstHeaderValue(value string) string {
	if i := strings.IndexByte(value, ','); i >= 0 {
		value = value[:i]
	}
	return strings.TrimSpace(value)
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
