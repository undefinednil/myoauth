package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/zenpk/my-oauth/dal"
	"github.com/zenpk/my-oauth/util"
)

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
	client, err := h.db.Clients.SelectByClientId(req.ClientId)
	if err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
	if client == nil {
		responseErrMsg(w, "invalid credentials")
		return
	}
	user, err := h.db.Users.SelectByName(req.Username)
	if err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
	if user == nil {
		responseErrMsg(w, "invalid credentials")
		return
	}
	passwordMatch, err := util.BCryptHashCheck(user.Password, req.Password)
	if err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
	if !passwordMatch {
		responseErrMsg(w, "invalid credentials")
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
		responseErrMsg(w, "invalid redirect uri")
		return
	}
	authorizationCode, err := h.authCodeStore.Generate(util.AuthorizationInfo{
		ClientId:      client.Id,
		UserId:        user.Id,
		RedirectUri:   req.Redirect,
		Scope:         normalizeScope(req.Scope),
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

func (h Handler) checkClient(clientId, clientSecret string) (*dal.Client, error) {
	client, err := h.db.Clients.SelectByClientId(clientId)
	if err != nil {
		h.logger.Println("internal error:", err)
		return nil, errors.New("internal error")
	}
	if client == nil {
		return nil, errors.New("client id doesn't exist")
	}
	secretMatch, err := util.BCryptHashCheck(client.Secret, clientSecret)
	if err != nil {
		h.logger.Println("internal error:", err)
		return nil, errors.New("internal error")
	}
	if !secretMatch {
		return nil, errors.New("incorrect client secret")
	}
	return client, nil
}
