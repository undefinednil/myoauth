package handler

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/zenpk/my-oauth/dal"
	"github.com/zenpk/my-oauth/util"
)

const adminCookieName = "admin_session"
const adminCSRFCookieName = "admin_csrf"
const adminSessionDuration = 1 * time.Hour

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
		responseErrMsg(w, "incorrect admin password")
		return
	}
	csrfToken, err := util.RandomHex(32)
	if err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
	expiry := time.Now().Add(adminSessionDuration)
	token := h.signAdminToken(expiry)
	http.SetCookie(w, &http.Cookie{
		Name:     adminCookieName,
		Value:    token,
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
	responseOk(w)
}

// verifyCSRF performs a constant-time double-submit cookie check: the
// X-CSRF-Token header must match the readable admin_csrf cookie.
func (h Handler) verifyCSRF(r *http.Request) bool {
	cookie, err := r.Cookie(adminCSRFCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	header := r.Header.Get("X-CSRF-Token")
	if header == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(header), []byte(cookie.Value)) == 1
}

func (h Handler) verifyAdminSession(r *http.Request) bool {
	cookie, err := r.Cookie(adminCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	return h.verifyAdminToken(cookie.Value)
}

// signAdminToken creates "expiry_unix|hmac(expiry_unix, adminPasswordHash)"
func (h Handler) signAdminToken(expiry time.Time) string {
	payload := fmt.Sprintf("%d", expiry.Unix())
	mac := hmac.New(sha256.New, []byte(h.conf.AdminPassword))
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	return payload + "|" + sig
}

func (h Handler) verifyAdminToken(token string) bool {
	var payload, sig string
	for i := len(token) - 1; i >= 0; i-- {
		if token[i] == '|' {
			payload = token[:i]
			sig = token[i+1:]
			break
		}
	}
	if payload == "" || sig == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(h.conf.AdminPassword))
	mac.Write([]byte(payload))
	expectedSig := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return false
	}
	expiryUnix, err := strconv.ParseInt(payload, 10, 64)
	if err != nil {
		return false
	}
	return time.Now().Unix() < expiryUnix
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
	if req.InvitationCode != h.conf.InvitationCode {
		responseErrMsg(w, "sorry, you need an invitation code or the code is incorrect")
		return
	}
	if req.Username == "" || req.Password == "" {
		responseInputError(w)
		return
	}
	if len(req.Username) > 256 {
		responseErrMsg(w, "username is too long")
		return
	}
	if hasControlChars(req.Username) {
		responseErrMsg(w, "username must not contain control characters")
		return
	}
	if len(req.Password) < h.conf.PasswordMinLength || len(req.Password) > 72 {
		responseErrMsg(w, "password must be between "+strconv.Itoa(h.conf.PasswordMinLength)+" and 72 characters")
		return
	}
	checkUser, err := h.db.Users.SelectByName(req.Username)
	if err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
	if checkUser != nil {
		responseErrMsg(w, "user already exists")
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
	if err := h.db.Users.Insert(user); err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
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
	clients, err := h.db.Clients.SelectAll()
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
		responseErrMsg(w, "refresh token age should be longer than access token age")
		return
	}
	oldClient, err := h.db.Clients.SelectByClientId(req.ClientId)
	if err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
	if oldClient != nil {
		responseErrMsg(w, "client id already exists")
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
	if err := h.db.Clients.Insert(client); err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
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
		responseErrMsg(w, "refresh token age should be longer than access token age")
		return
	}
	existing, err := h.db.Clients.SelectById(req.Id)
	if err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
	if existing == nil {
		responseErrMsg(w, "client doesn't exist")
		return
	}
	if req.ClientId != existing.ClientId {
		other, err := h.db.Clients.SelectByClientId(req.ClientId)
		if err != nil {
			responseInternalError(w, h.logger, err)
			return
		}
		if other != nil && other.Id != req.Id {
			responseErrMsg(w, "client id already exists")
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
	if err := h.db.Clients.UpdateById(client); err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
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
	if err := h.db.Clients.DeleteById(req.Id); err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
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
		if err := h.db.RefreshTokens.DeleteAll(); err != nil {
			responseInternalError(w, h.logger, err)
			return
		}
		// Invalidate outstanding access tokens too, durably (FIX F9).
		if err := h.db.TokenStore.RevokeAccessTokensByClient(0); err != nil {
			responseInternalError(w, h.logger, err)
			return
		}
		h.logger.Printf("admin revoked sessions | clientId=all | ip=%v\n", clientIP(r, h.conf.TrustProxy))
	} else {
		if err := h.db.RefreshTokens.DeleteByClient(req.ClientId); err != nil {
			responseInternalError(w, h.logger, err)
			return
		}
		if err := h.db.TokenStore.RevokeAccessTokensByClient(req.ClientId); err != nil {
			responseInternalError(w, h.logger, err)
			return
		}
		h.logger.Printf("admin revoked sessions | clientId=%v | ip=%v\n", req.ClientId, clientIP(r, h.conf.TrustProxy))
	}
	responseOk(w)
}
