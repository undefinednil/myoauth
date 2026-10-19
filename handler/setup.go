package handler

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/undefinednil/myoauth/dal"
	"github.com/undefinednil/myoauth/util"
)

const adminCookieName = "admin_session"
const adminCSRFCookieName = "admin_csrf"
const adminSessionDuration = 1 * time.Hour

// adminSessionIDBytes is the entropy of the opaque session id; 32 bytes = 256
// bits, so guessing a live session is infeasible.
const adminSessionIDBytes = 32

// adminSessionSweepInterval throttles the lazy removal of expired sessions so a
// busy console does not scan the map on every request.
const adminSessionSweepInterval = 1 * time.Minute

// adminSessionEntry is one live admin console session.
type adminSessionEntry struct {
	csrfToken string
	expiresAt time.Time
}

// adminSessionStore keeps admin console sessions server-side, guarded by a
// mutex. The cookie only ever carries the random session id, so a session can
// be revoked by deleting its entry (logout) instead of relying on a
// deterministic HMAC whose value was identical for two logins in the same
// second. Expired entries are dropped lazily. The store is in-memory only,
// which means a server restart invalidates every admin session and all admins
// must sign in again.
type adminSessionStore struct {
	mu        sync.Mutex
	sessions  map[string]*adminSessionEntry
	lastSweep time.Time
}

func newAdminSessionStore() *adminSessionStore {
	return &adminSessionStore{sessions: make(map[string]*adminSessionEntry)}
}

// create mints a new session id and its bound CSRF token, stores them and
// returns both.
func (s *adminSessionStore) create(ttl time.Duration) (id, csrf string, err error) {
	id, err = util.RandomHex(adminSessionIDBytes)
	if err != nil {
		return "", "", err
	}
	csrf, err = util.RandomHex(32)
	if err != nil {
		return "", "", err
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
	s.sessions[id] = &adminSessionEntry{csrfToken: csrf, expiresAt: now.Add(ttl)}
	return id, csrf, nil
}

// get returns the live entry for a session id, deleting it when expired.
func (s *adminSessionStore) get(id string) (*adminSessionEntry, bool) {
	if id == "" {
		return nil, false
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
	entry, ok := s.sessions[id]
	if !ok {
		return nil, false
	}
	if !now.Before(entry.expiresAt) {
		delete(s.sessions, id)
		return nil, false
	}
	return entry, true
}

// delete revokes a session immediately (admin logout).
func (s *adminSessionStore) delete(id string) {
	if id == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

// sweepLocked drops expired entries at most once per sweep interval.
func (s *adminSessionStore) sweepLocked(now time.Time) {
	if now.Sub(s.lastSweep) < adminSessionSweepInterval {
		return
	}
	for id, entry := range s.sessions {
		if !now.Before(entry.expiresAt) {
			delete(s.sessions, id)
		}
	}
	s.lastSweep = now
}

type adminLoginReq struct {
	AdminPassword string `json:"adminPassword"`
}

type adminLoginResp struct {
	commonResp
	CsrfToken string `json:"csrfToken"`
}

func (h Handler) adminLogin(w http.ResponseWriter, r *http.Request) {
	var req adminLoginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		responseInputError(w, err)
		return
	}
	if req.AdminPassword == "" {
		responseInputError(w)
		return
	}
	passwordMatch, err := util.BCryptHashCheck(h.conf.AdminPassword, req.AdminPassword)
	if err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
	if !passwordMatch {
		metricAuthFailuresAdmin.Add(1)
		h.logger.Warnf("admin login failed | ip=%v\n", clientIP(r, h.conf.TrustProxy))
		responseErrStatus(w, "incorrect admin password", http.StatusUnauthorized)
		return
	}
	sessionID, csrfToken, err := h.adminSessions.create(adminSessionDuration)
	if err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
	h.setAdminCookies(w, sessionID, csrfToken)
	h.logger.Infof("admin login success | ip=%v\n", clientIP(r, h.conf.TrustProxy))
	responseJson(w, adminLoginResp{
		commonResp: genOkResponse(),
		CsrfToken:  csrfToken,
	})
}

func (h Handler) adminLogout(w http.ResponseWriter, r *http.Request) {
	if !h.verifyCSRF(r) {
		responseJson(w, commonResp{Ok: false, Msg: "invalid csrf token"}, http.StatusForbidden)
		return
	}
	// Deleting the server-side entry is what actually ends the session; the
	// cookie clearing below only tidies up the browser.
	if cookie, err := r.Cookie(adminCookieName); err == nil && cookie.Value != "" {
		h.adminSessions.delete(cookie.Value)
	}
	h.clearAdminCookies(w)
	h.logger.Infof("admin logout | ip=%v\n", clientIP(r, h.conf.TrustProxy))
	responseOk(w)
}

// setAdminCookies writes the opaque session id (HttpOnly) and the bound CSRF
// token (readable by the SPA for the double-submit header).
func (h Handler) setAdminCookies(w http.ResponseWriter, sessionID, csrfToken string) {
	http.SetCookie(w, &http.Cookie{
		Name:     adminCookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.conf.SecureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(adminSessionDuration.Seconds()),
	})
	// Readable by the SPA (double-submit CSRF token), hence not HttpOnly.
	http.SetCookie(w, &http.Cookie{
		Name:     adminCSRFCookieName,
		Value:    csrfToken,
		Path:     "/",
		HttpOnly: false,
		Secure:   h.conf.SecureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(adminSessionDuration.Seconds()),
	})
}

func (h Handler) clearAdminCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     adminCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     adminCSRFCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: false,
		MaxAge:   -1,
	})
}

// adminSession resolves the server-side session behind the admin_session
// cookie, or (nil, false) when it is missing or expired.
func (h Handler) adminSession(r *http.Request) (*adminSessionEntry, bool) {
	if h.adminSessions == nil {
		return nil, false
	}
	cookie, err := r.Cookie(adminCookieName)
	if err != nil || cookie.Value == "" {
		return nil, false
	}
	return h.adminSessions.get(cookie.Value)
}

func (h Handler) verifyAdminSession(r *http.Request) bool {
	_, ok := h.adminSession(r)
	return ok
}

// verifyCSRF performs a constant-time double-submit check where both the
// X-CSRF-Token header and the readable admin_csrf cookie must equal the CSRF
// token bound to the server-side session. Binding to the session means a stale
// or forged cookie pair from another session can never authorize a request.
func (h Handler) verifyCSRF(r *http.Request) bool {
	entry, ok := h.adminSession(r)
	if !ok {
		return false
	}
	cookie, err := r.Cookie(adminCSRFCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	header := r.Header.Get("X-CSRF-Token")
	if header == "" {
		return false
	}
	cookieMatch := subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(entry.csrfToken)) == 1
	headerMatch := subtle.ConstantTimeCompare([]byte(header), []byte(entry.csrfToken)) == 1
	return cookieMatch && headerMatch
}

// constantTimeStringEqual compares two strings in constant time (after hashing
// both to a fixed length) so the invitation code comparison cannot leak its
// length or content through timing.
func constantTimeStringEqual(a, b string) bool {
	sumA := sha256.Sum256([]byte(a))
	sumB := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(sumA[:], sumB[:]) == 1
}

// validateRedirectURIs validates the comma-separated redirect URI list of a
// client before it is stored. Every entry must be an absolute http(s) URL with
// a host and no fragment and no userinfo; anything else (javascript:, data:,
// //host, https://user:pass@host/...) is rejected so a bogus URI can never be
// stored and later redirected to. Existing rows are not migrated: only new
// writes are validated.
func validateRedirectURIs(raw string) error {
	for _, part := range strings.Split(raw, ",") {
		uri := strings.TrimSpace(part)
		if uri == "" {
			return errors.New("redirect uri must not be empty")
		}
		u, err := url.Parse(uri)
		if err != nil {
			return errors.New("redirect uri " + strconv.Quote(uri) + " is not a valid URL")
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return errors.New("redirect uri " + strconv.Quote(uri) + " must use the http or https scheme")
		}
		if u.Host == "" {
			return errors.New("redirect uri " + strconv.Quote(uri) + " must include a host")
		}
		if u.Fragment != "" {
			return errors.New("redirect uri " + strconv.Quote(uri) + " must not contain a fragment")
		}
		if u.User != nil {
			return errors.New("redirect uri " + strconv.Quote(uri) + " must not contain userinfo")
		}
	}
	return nil
}

type registerReq struct {
	Username       string `json:"username"`
	Password       string `json:"password"`
	InvitationCode string `json:"invitationCode"`
}

func (h Handler) register(w http.ResponseWriter, r *http.Request) {
	var req registerReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		responseInputError(w, err)
		return
	}
	// Constant-time comparison: a plain != would let an attacker infer the code
	// prefix from response timing (item 3).
	if !constantTimeStringEqual(req.InvitationCode, h.conf.InvitationCode) {
		h.logger.Warnf("registration rejected: invalid invitation code | ip=%v\n", clientIP(r, h.conf.TrustProxy))
		responseErrStatus(w, "sorry, you need an invitation code or the code is incorrect", http.StatusForbidden)
		return
	}
	if req.Username == "" || req.Password == "" {
		responseInputError(w)
		return
	}
	if len(req.Username) > 256 {
		responseErrStatus(w, "username is too long", http.StatusBadRequest)
		return
	}
	if hasControlChars(req.Username) {
		responseErrStatus(w, "username must not contain control characters", http.StatusBadRequest)
		return
	}
	if len(req.Password) < h.conf.PasswordMinLength || len(req.Password) > 72 {
		responseErrStatus(w, "password must be between "+strconv.Itoa(h.conf.PasswordMinLength)+" and 72 characters", http.StatusBadRequest)
		return
	}
	checkUser, err := h.db.Users.SelectByName(r.Context(), req.Username)
	if err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
	if checkUser != nil {
		responseErrStatus(w, "user already exists", http.StatusConflict)
		return
	}
	passwordHash, err := util.BCryptPassword(req.Password)
	if err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
	user := &dal.User{
		Uuid:     uuid.New().String(),
		Name:     req.Username,
		Password: passwordHash,
	}
	if err := h.db.Users.Insert(r.Context(), user); err != nil {
		// The pre-check above is best-effort; the unique index is the real
		// guard, so a concurrent duplicate still maps to 409 instead of 500.
		if dal.IsUniqueConstraintError(err) {
			responseErrStatus(w, "user already exists", http.StatusConflict)
			return
		}
		responseInternalError(w, h.logger, err)
		return
	}
	metricRegistrations.Add(1)
	h.logger.Infof("user registered | name=%q | ip=%v\n", req.Username, clientIP(r, h.conf.TrustProxy))
	responseOk(w)
}

type clientWithoutSecret struct {
	Id              int64  `json:"id"`
	ClientId        string `json:"clientId"`
	Redirects       string `json:"redirects"`
	AccessTokenAge  int64  `json:"accessTokenAge"`
	RefreshTokenAge int64  `json:"refreshTokenAge"`
}

type clientListResp struct {
	commonResp
	Clients []clientWithoutSecret `json:"clients"`
}

func (h Handler) clientList(w http.ResponseWriter, r *http.Request) {
	if !h.verifyAdminSession(r) {
		responseJson(w, commonResp{Ok: false, Msg: "unauthorized"}, http.StatusUnauthorized)
		return
	}
	clients, err := h.db.Clients.SelectAll(r.Context())
	if err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
	clientsConverted := make([]clientWithoutSecret, 0)
	for _, client := range clients {
		converted := clientWithoutSecret{
			Id:              client.Id,
			ClientId:        client.ClientId,
			Redirects:       client.Redirects,
			AccessTokenAge:  client.AccessTokenAge,
			RefreshTokenAge: client.RefreshTokenAge,
		}
		clientsConverted = append(clientsConverted, converted)
	}
	responseJson(w, clientListResp{
		commonResp: genOkResponse(),
		Clients:    clientsConverted,
	})
}

type clientCreateReq struct {
	ClientId        string `json:"clientId"`
	Secret          string `json:"secret"`
	Redirects       string `json:"redirects"`
	AccessTokenAge  int64  `json:"accessTokenAge"`
	RefreshTokenAge int64  `json:"refreshTokenAge"`
}

func (h Handler) clientCreate(w http.ResponseWriter, r *http.Request) {
	if !h.verifyAdminSession(r) {
		responseJson(w, commonResp{Ok: false, Msg: "unauthorized"}, http.StatusUnauthorized)
		return
	}
	if !h.verifyCSRF(r) {
		responseJson(w, commonResp{Ok: false, Msg: "invalid csrf token"}, http.StatusForbidden)
		return
	}
	var req clientCreateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		responseInputError(w, err)
		return
	}
	if req.ClientId == "" || req.Secret == "" || req.Redirects == "" || req.AccessTokenAge <= 0 || req.RefreshTokenAge <= 0 {
		responseInputError(w)
		return
	}
	if len(req.ClientId) > 256 || len(req.Secret) > 256 || len(req.Redirects) > 2048 {
		responseInputError(w)
		return
	}
	if req.RefreshTokenAge <= req.AccessTokenAge {
		responseErrStatus(w, "refresh token age should be longer than access token age", http.StatusBadRequest)
		return
	}
	if err := validateRedirectURIs(req.Redirects); err != nil {
		responseErrStatus(w, err.Error(), http.StatusBadRequest)
		return
	}
	hashedSecret, err := util.BCryptPassword(req.Secret)
	if err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
	client := &dal.Client{
		ClientId:        req.ClientId,
		Secret:          hashedSecret,
		Redirects:       req.Redirects,
		AccessTokenAge:  req.AccessTokenAge,
		RefreshTokenAge: req.RefreshTokenAge,
	}
	// A single insert relying on the unique index replaces the old
	// check-then-insert, which two concurrent admins could race through and
	// create duplicates (item 13). The unique violation maps to 409.
	if err := h.db.Clients.Insert(r.Context(), client); err != nil {
		if errors.Is(err, dal.ErrClientExists) || dal.IsUniqueConstraintError(err) {
			responseErrStatus(w, "client id already exists", http.StatusConflict)
			return
		}
		responseInternalError(w, h.logger, err)
		return
	}
	h.logger.Infof("admin created client | clientId=%q | ip=%v\n", req.ClientId, clientIP(r, h.conf.TrustProxy))
	responseOk(w)
}

type clientUpdateReq struct {
	Id              int64  `json:"id"`
	ClientId        string `json:"clientId"`
	Secret          string `json:"secret"`
	Redirects       string `json:"redirects"`
	AccessTokenAge  int64  `json:"accessTokenAge"`
	RefreshTokenAge int64  `json:"refreshTokenAge"`
}

func (h Handler) clientUpdate(w http.ResponseWriter, r *http.Request) {
	if !h.verifyAdminSession(r) {
		responseJson(w, commonResp{Ok: false, Msg: "unauthorized"}, http.StatusUnauthorized)
		return
	}
	if !h.verifyCSRF(r) {
		responseJson(w, commonResp{Ok: false, Msg: "invalid csrf token"}, http.StatusForbidden)
		return
	}
	var req clientUpdateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		responseInputError(w, err)
		return
	}
	if req.Id <= 0 || req.ClientId == "" || req.Redirects == "" || req.AccessTokenAge <= 0 || req.RefreshTokenAge <= 0 {
		responseInputError(w)
		return
	}
	if len(req.ClientId) > 256 || len(req.Secret) > 256 || len(req.Redirects) > 2048 {
		responseInputError(w)
		return
	}
	if req.RefreshTokenAge <= req.AccessTokenAge {
		responseErrStatus(w, "refresh token age should be longer than access token age", http.StatusBadRequest)
		return
	}
	if err := validateRedirectURIs(req.Redirects); err != nil {
		responseErrStatus(w, err.Error(), http.StatusBadRequest)
		return
	}
	existing, err := h.db.Clients.SelectById(r.Context(), req.Id)
	if err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
	if existing == nil {
		responseErrStatus(w, "client doesn't exist", http.StatusNotFound)
		return
	}
	if req.ClientId != existing.ClientId {
		other, err := h.db.Clients.SelectByClientId(r.Context(), req.ClientId)
		if err != nil {
			responseInternalError(w, h.logger, err)
			return
		}
		if other != nil && other.Id != req.Id {
			responseErrStatus(w, "client id already exists", http.StatusConflict)
			return
		}
	}
	secret := existing.Secret
	if req.Secret != "" {
		hashedSecret, err := util.BCryptPassword(req.Secret)
		if err != nil {
			responseInternalError(w, h.logger, err)
			return
		}
		secret = hashedSecret
	}
	client := &dal.Client{
		Id:              req.Id,
		ClientId:        req.ClientId,
		Secret:          secret,
		Redirects:       req.Redirects,
		AccessTokenAge:  req.AccessTokenAge,
		RefreshTokenAge: req.RefreshTokenAge,
	}
	if err := h.db.Clients.UpdateById(r.Context(), client); err != nil {
		// The unique index also catches a rename race that slips past the
		// pre-check above; report it as a conflict rather than a 500.
		if errors.Is(err, dal.ErrClientExists) || dal.IsUniqueConstraintError(err) {
			responseErrStatus(w, "client id already exists", http.StatusConflict)
			return
		}
		responseInternalError(w, h.logger, err)
		return
	}
	h.logger.Infof("admin updated client | clientId=%q | ip=%v\n", req.ClientId, clientIP(r, h.conf.TrustProxy))
	responseOk(w)
}

type clientDeleteReq struct {
	Id int64 `json:"id"`
}

func (h Handler) clientDelete(w http.ResponseWriter, r *http.Request) {
	if !h.verifyAdminSession(r) {
		responseJson(w, commonResp{Ok: false, Msg: "unauthorized"}, http.StatusUnauthorized)
		return
	}
	if !h.verifyCSRF(r) {
		responseJson(w, commonResp{Ok: false, Msg: "invalid csrf token"}, http.StatusForbidden)
		return
	}
	var req clientDeleteReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		responseInputError(w, err)
		return
	}
	if req.Id <= 0 {
		responseInputError(w)
		return
	}
	if err := h.db.Clients.DeleteById(r.Context(), req.Id); err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
	h.logger.Infof("admin deleted client | id=%v | ip=%v\n", req.Id, clientIP(r, h.conf.TrustProxy))
	responseOk(w)
}

type sessionRevokeReq struct {
	ClientId int64 `json:"clientId"`
}

func (h Handler) sessionRevoke(w http.ResponseWriter, r *http.Request) {
	if !h.verifyAdminSession(r) {
		responseJson(w, commonResp{Ok: false, Msg: "unauthorized"}, http.StatusUnauthorized)
		return
	}
	if !h.verifyCSRF(r) {
		responseJson(w, commonResp{Ok: false, Msg: "invalid csrf token"}, http.StatusForbidden)
		return
	}
	var req sessionRevokeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		responseInputError(w, err)
		return
	}
	if req.ClientId < 0 {
		responseInputError(w)
		return
	}
	if req.ClientId == 0 {
		if err := h.db.RefreshTokens.DeleteAll(r.Context()); err != nil {
			responseInternalError(w, h.logger, err)
			return
		}
		// Invalidate outstanding access tokens too, durably (FIX F9).
		if err := h.db.TokenStore.RevokeAccessTokensByClient(r.Context(), 0); err != nil {
			responseInternalError(w, h.logger, err)
			return
		}
		h.logger.Infof("admin revoked sessions | clientId=all | ip=%v\n", clientIP(r, h.conf.TrustProxy))
	} else {
		if err := h.db.RefreshTokens.DeleteByClient(r.Context(), req.ClientId); err != nil {
			responseInternalError(w, h.logger, err)
			return
		}
		if err := h.db.TokenStore.RevokeAccessTokensByClient(r.Context(), req.ClientId); err != nil {
			responseInternalError(w, h.logger, err)
			return
		}
		h.logger.Infof("admin revoked sessions | clientId=%v | ip=%v\n", req.ClientId, clientIP(r, h.conf.TrustProxy))
	}
	responseOk(w)
}
