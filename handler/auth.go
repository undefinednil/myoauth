package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/undefinednil/myoauth/dal"
	"github.com/undefinednil/myoauth/util"
)

// dummyPasswordHash is a valid bcrypt hash (cost 12, matching
// util.BCryptPassword) of a fixed throwaway string that is never a real
// credential. Every time a lookup fails (unknown username, unknown client_id)
// the handler still runs bcrypt.CompareHashAndPassword against this hash, so
// the response time of "user does not exist" is indistinguishable from
// "wrong password" and the endpoint cannot be used to enumerate accounts.
const dummyPasswordHash = "$2a$12$PUK1y0bMxYl67Pr7oUZ4IONJXmr5WUUK2ubQL6oTOuXV1.eZNK4zi"

// invalidCredentialsMsg is the single uniform login error for both an unknown
// username and a wrong password; it must not be varied or the message itself
// becomes an enumeration oracle.
const invalidCredentialsMsg = "invalid username or password"

// invalidClientMsg is the single uniform error returned for both an unknown
// client_id and a wrong client secret, for the same timing/enumeration reason.
const invalidClientMsg = "invalid client credentials"

type loginReq struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	ClientId      string `json:"clientId"`
	CodeChallenge string `json:"codeChallenge"`
	Redirect      string `json:"redirect"`
	Scope         string `json:"scope"`
	State         string `json:"state"`
	Nonce         string `json:"nonce"`
}

type loginResp struct {
	commonResp
	AuthorizationCode string `json:"authorizationCode"`
}

func (h Handler) login(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		responseInputError(w, err)
		return
	}
	if req.Username == "" || req.Password == "" || req.ClientId == "" || req.CodeChallenge == "" || req.Redirect == "" {
		responseInputError(w)
		return
	}
	if len(req.Username) > 256 || len(req.Password) > 72 || len(req.CodeChallenge) > 512 || len(req.Redirect) > 2048 || len(req.Scope) > 1024 || len(req.State) > 2048 || len(req.Nonce) > 2048 {
		responseInputError(w)
		return
	}
	client, err := h.db.Clients.SelectByClientId(r.Context(), req.ClientId)
	if err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
	if client == nil {
		// An unknown client_id is a malformed sign-in request (the SPA always
		// gets it from /authorize, which validates it), not a credential
		// failure, so answer 400. client_ids are public identifiers, so this
		// does not leak anything sensitive.
		responseErrStatus(w, "unknown client", http.StatusBadRequest)
		return
	}
	user, err := h.db.Users.SelectByName(r.Context(), req.Username)
	if err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
	// Always burn one bcrypt comparison, even when the username does not exist,
	// so response timing cannot reveal account existence (item 4). The compare
	// runs against the real hash when there is a user and against the dummy
	// hash otherwise.
	passwordHash := dummyPasswordHash
	if user != nil {
		passwordHash = user.Password
	}
	passwordMatch, err := util.BCryptHashCheck(passwordHash, req.Password)
	if err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
	if user == nil || !passwordMatch {
		metricAuthFailuresUser.Add(1)
		h.logger.Warnf("user login failed | ip=%v\n", clientIP(r, h.conf.TrustProxy))
		responseErrStatus(w, invalidCredentialsMsg, http.StatusUnauthorized)
		return
	}
	redirects := strings.Split(client.Redirects, ",")
	redirectValid := false
	for _, redirect := range redirects {
		if strings.Trim(redirect, " ") == req.Redirect {
			redirectValid = true
			break
		}
	}
	if !redirectValid {
		responseErrStatus(w, "invalid redirect uri", http.StatusBadRequest)
		return
	}
	// The scope is persisted on the authorization code and later on the refresh
	// token, so it must be one the provider actually implements; the /authorize
	// endpoint performs the same check, but a direct /auth/login call could
	// otherwise smuggle an arbitrary scope into the stored grant (item 14).
	scope := normalizeScope(req.Scope)
	if err := util.ValidateScopes(strings.Fields(scope)); err != nil {
		responseErrStatus(w, err.Error(), http.StatusBadRequest)
		return
	}
	authorizationCode, err := h.authCodeStore.Generate(util.AuthorizationInfo{
		ClientId:      client.Id,
		UserId:        user.Id,
		RedirectUri:   req.Redirect,
		Scope:         scope,
		State:         req.State,
		Nonce:         req.Nonce,
		CodeChallenge: req.CodeChallenge,
	})
	if err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
	sw, _ := w.(*statusResponseWriter)
	sw.WriteUsername(user.Name)
	responseJson(sw, loginResp{
		commonResp:        genOkResponse(),
		AuthorizationCode: authorizationCode,
	})
}

// verifyClient authenticates a client by id and secret. An unknown client_id
// still burns a bcrypt comparison against the dummy hash and returns the exact
// same error as a wrong secret, so neither the error message nor the response
// time distinguishes the two cases. Callers with a request in hand pass
// r.Context() so the lookup honors client disconnect/deadline.
func (h Handler) verifyClient(ctx context.Context, clientId, clientSecret string) (*dal.Client, error) {
	client, err := h.db.Clients.SelectByClientId(ctx, clientId)
	if err != nil {
		h.logger.Errorf("client lookup failed: %v\n", err)
		return nil, errors.New("internal error")
	}
	secretHash := dummyPasswordHash
	if client != nil {
		secretHash = client.Secret
	}
	secretMatch, err := util.BCryptHashCheck(secretHash, clientSecret)
	if err != nil {
		h.logger.Errorf("client secret check failed: %v\n", err)
		return nil, errors.New("internal error")
	}
	if client == nil || !secretMatch {
		return nil, errors.New(invalidClientMsg)
	}
	return client, nil
}
