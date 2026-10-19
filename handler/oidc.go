package handler

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cristalhq/jwt/v5"
	"github.com/zenpk/my-oauth/dal"
	"github.com/zenpk/my-oauth/token"
)

type oidcDiscoveryResp struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
}

func (h Handler) oidcDiscovery(w http.ResponseWriter, r *http.Request) {
	issuer := h.oidcIssuer()
	responseJson(w, oidcDiscoveryResp{
		Issuer:                            issuer,
		AuthorizationEndpoint:             issuer + "/authorize",
		TokenEndpoint:                     issuer + "/token",
		UserinfoEndpoint:                  issuer + "/userinfo",
		JwksURI:                           issuer + "/.well-known/jwks.json",
		ResponseTypesSupported:            []string{"code"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		ScopesSupported:                   []string{"openid", "profile"},
		ClaimsSupported:                   []string{"sub", "name"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post", "client_secret_basic"},
		CodeChallengeMethodsSupported:     []string{"S256"},
	})
}

type oidcJWKSResp struct {
	Keys []*token.Jwk `json:"keys"`
}

func (h Handler) oidcJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=86400")
	jwk, err := h.tk.GetJWK()
	if err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
	responseJson(w, oidcJWKSResp{
		Keys: []*token.Jwk{jwk},
	})
}

func (h Handler) oidcAuthorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	responseType := query.Get("response_type")
	clientId := query.Get("client_id")
	redirectURI := query.Get("redirect_uri")
	scope := normalizeScope(query.Get("scope"))
	state := query.Get("state")
	nonce := query.Get("nonce")
	codeChallenge := query.Get("code_challenge")
	codeChallengeMethod := query.Get("code_challenge_method")

	if clientId == "" || redirectURI == "" || responseType == "" || state == "" {
		responseOIDCError(w, http.StatusBadRequest, "invalid_request", "missing required query params")
		return
	}
	client, err := h.db.Clients.SelectByClientId(clientId)
	if err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
	if client == nil {
		responseOIDCError(w, http.StatusBadRequest, "invalid_client", "client does not exist")
		return
	}
	if !isRedirectAllowed(client.Redirects, redirectURI) {
		responseOIDCError(w, http.StatusBadRequest, "invalid_request", "redirect_uri is not allowed")
		return
	}
	if responseType != "code" {
		redirectOIDCError(w, r, redirectURI, state, "unsupported_response_type", "only response_type=code is supported")
		return
	}
	if !scopeContains(scope, "openid") {
		redirectOIDCError(w, r, redirectURI, state, "invalid_scope", "scope must contain openid")
		return
	}
	if codeChallenge == "" {
		redirectOIDCError(w, r, redirectURI, state, "invalid_request", "code_challenge is required")
		return
	}
	if codeChallengeMethod == "" {
		codeChallengeMethod = "S256"
	}
	if codeChallengeMethod != "S256" {
		redirectOIDCError(w, r, redirectURI, state, "invalid_request", "only code_challenge_method=S256 is supported")
		return
	}

	loginURL, err := url.Parse(h.oidcLoginURL())
	if err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
	loginQuery := loginURL.Query()
	loginQuery.Set("client_id", clientId)
	loginQuery.Set("redirect_uri", redirectURI)
	loginQuery.Set("code_challenge", codeChallenge)
	loginQuery.Set("code_challenge_method", codeChallengeMethod)
	loginQuery.Set("scope", scope)
	loginQuery.Set("state", state)
	if nonce != "" {
		loginQuery.Set("nonce", nonce)
	}
	loginURL.RawQuery = loginQuery.Encode()
	http.Redirect(w, r, loginURL.String(), http.StatusFound)
}

type oidcTokenResp struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

func (h Handler) oidcToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		responseOIDCError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}
	grantType := r.PostForm.Get("grant_type")
	if grantType == "" {
		responseOIDCError(w, http.StatusBadRequest, "invalid_request", "grant_type is required")
		return
	}

	clientId, clientSecret, err := oidcClientCredentials(r)
	if err != nil {
		responseOIDCError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}
	client, err := h.checkClient(clientId, clientSecret)
	if err != nil {
		responseOIDCError(w, http.StatusUnauthorized, "invalid_client", "invalid client credentials")
		return
	}

	switch grantType {
	case "authorization_code":
		h.oidcTokenAuthorizationCode(w, r, client)
	case "refresh_token":
		h.oidcTokenRefresh(w, r, client)
	default:
		responseOIDCError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant_type")
	}
}

func (h Handler) oidcTokenAuthorizationCode(w http.ResponseWriter, r *http.Request, client *dal.Client) {
	code := r.PostForm.Get("code")
	codeVerifier := r.PostForm.Get("code_verifier")
	redirectURI := r.PostForm.Get("redirect_uri")
	if code == "" || codeVerifier == "" || redirectURI == "" {
		responseOIDCError(w, http.StatusBadRequest, "invalid_request", "code, code_verifier, and redirect_uri are required")
		return
	}

	info, err := h.authCodeStore.Verify(code, codeVerifier)
	if err != nil {
		responseOIDCError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		return
	}
	if info.ClientId != client.Id {
		responseOIDCError(w, http.StatusBadRequest, "invalid_grant", "client mismatch")
		return
	}
	if redirectURI != info.RedirectUri {
		responseOIDCError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}

	user, err := h.db.Users.SelectById(info.UserId)
	if err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
	if user == nil {
		responseOIDCError(w, http.StatusBadRequest, "invalid_grant", "user not found")
		return
	}

	accessToken, expiresIn, err := h.issueAccessToken(user, client)
	if err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
	refreshToken, err := h.sv.GenAndInsertRefreshToken(client, user)
	if err != nil {
		responseInternalError(w, h.logger, err)
		return
	}

	resp := oidcTokenResp{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
		RefreshToken: refreshToken,
		Scope:        info.Scope,
	}
	if scopeContains(info.Scope, "openid") {
		idToken, err := h.issueIDToken(user, client, info.Nonce)
		if err != nil {
			responseInternalError(w, h.logger, err)
			return
		}
		resp.IDToken = idToken
	}

	sw, _ := w.(*statusResponseWriter)
	sw.WriteUsername(user.Name)
	responseJson(sw, resp)
}

func (h Handler) oidcTokenRefresh(w http.ResponseWriter, r *http.Request, client *dal.Client) {
	refreshToken := r.PostForm.Get("refresh_token")
	if refreshToken == "" {
		responseOIDCError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}

	oldRefreshToken, err := h.db.RefreshTokens.SelectByToken(refreshToken)
	if err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
	if oldRefreshToken == nil {
		responseOIDCError(w, http.StatusBadRequest, "invalid_grant", "refresh token doesn't exist")
		return
	}
	if oldRefreshToken.ExpireTime != nil && oldRefreshToken.ExpireTime.Before(time.Now()) {
		_ = h.db.RefreshTokens.DeleteById(oldRefreshToken.Id)
		responseOIDCError(w, http.StatusBadRequest, "invalid_grant", "refresh token expired")
		return
	}
	if oldRefreshToken.ClientId != client.Id {
		responseOIDCError(w, http.StatusBadRequest, "invalid_grant", "client mismatch")
		return
	}

	user, err := h.db.Users.SelectById(oldRefreshToken.UserId)
	if err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
	if user == nil {
		responseOIDCError(w, http.StatusBadRequest, "invalid_grant", "user not found")
		return
	}

	if err := h.db.RefreshTokens.DeleteById(oldRefreshToken.Id); err != nil {
		responseInternalError(w, h.logger, err)
		return
	}

	accessToken, expiresIn, err := h.issueAccessToken(user, client)
	if err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
	newRefreshToken, err := h.sv.GenAndInsertRefreshToken(client, user)
	if err != nil {
		responseInternalError(w, h.logger, err)
		return
	}

	sw, _ := w.(*statusResponseWriter)
	sw.WriteUsername(user.Name)
	responseJson(sw, oidcTokenResp{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
		RefreshToken: newRefreshToken,
	})
}

type oidcUserinfoResp struct {
	Sub  string `json:"sub"`
	Name string `json:"name,omitempty"`
}

func (h Handler) oidcUserinfo(w http.ResponseWriter, r *http.Request) {
	accessToken, err := bearerToken(r)
	if err != nil {
		responseOIDCError(w, http.StatusUnauthorized, "invalid_token", err.Error())
		return
	}
	claims, ok, err := h.tk.ParseAndVerifyJwt(accessToken)
	if err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
	if !ok {
		responseOIDCError(w, http.StatusUnauthorized, "invalid_token", "token is invalid")
		return
	}
	if claims.Subject == "" {
		responseOIDCError(w, http.StatusUnauthorized, "invalid_token", "subject is missing")
		return
	}
	user, err := h.db.Users.SelectByUuid(claims.Subject)
	if err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
	if user == nil {
		responseOIDCError(w, http.StatusUnauthorized, "invalid_token", "user not found")
		return
	}
	sw, _ := w.(*statusResponseWriter)
	sw.WriteUsername(user.Name)
	responseJson(sw, oidcUserinfoResp{
		Sub:  user.Uuid,
		Name: user.Name,
	})
}

func responseOIDCError(w http.ResponseWriter, status int, code, description string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer error="`+code+`"`)
	}
	responseJson(w, map[string]string{
		"error":             code,
		"error_description": description,
	}, status)
}

func redirectOIDCError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, description string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		responseOIDCError(w, http.StatusBadRequest, "invalid_request", "invalid redirect_uri")
		return
	}
	query := u.Query()
	query.Set("error", code)
	query.Set("error_description", description)
	if state != "" {
		query.Set("state", state)
	}
	u.RawQuery = query.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func isRedirectAllowed(redirectsCSV, redirectURI string) bool {
	for _, redirect := range strings.Split(redirectsCSV, ",") {
		if strings.TrimSpace(redirect) == redirectURI {
			return true
		}
	}
	return false
}

func normalizeScope(scope string) string {
	fields := strings.Fields(scope)
	if len(fields) == 0 {
		return "openid profile"
	}
	return strings.Join(fields, " ")
}

func scopeContains(scope, want string) bool {
	for _, current := range strings.Fields(scope) {
		if current == want {
			return true
		}
	}
	return false
}

func oidcClientCredentials(r *http.Request) (string, string, error) {
	clientId := r.PostForm.Get("client_id")
	clientSecret := r.PostForm.Get("client_secret")

	auth := r.Header.Get("Authorization")
	if auth == "" {
		if clientId == "" || clientSecret == "" {
			return "", "", errors.New("missing client credentials")
		}
		return clientId, clientSecret, nil
	}

	prefix := "Basic "
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return "", "", errors.New("unsupported authorization scheme")
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(auth[len(prefix):]))
	if err != nil {
		return "", "", errors.New("invalid basic auth encoding")
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", errors.New("invalid basic auth credentials")
	}
	if clientId != "" && clientId != parts[0] {
		return "", "", errors.New("client_id mismatch")
	}
	if clientSecret != "" && clientSecret != parts[1] {
		return "", "", errors.New("client_secret mismatch")
	}
	return parts[0], parts[1], nil
}

func bearerToken(r *http.Request) (string, error) {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if auth == "" {
		return "", errors.New("missing authorization header")
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", errors.New("invalid authorization header")
	}
	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", errors.New("missing bearer token")
	}
	return token, nil
}

func (h Handler) issueAccessToken(user *dal.User, client *dal.Client) (string, int64, error) {
	now := time.Now()
	expireTime := now.Add(time.Duration(client.AccessTokenAge) * time.Hour)
	claims := &token.AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: &jwt.NumericDate{Time: expireTime},
			IssuedAt:  &jwt.NumericDate{Time: now},
			Issuer:    h.tokenIssuer(),
			Subject:   user.Uuid,
			Audience:  jwt.Audience{client.ClientId},
		},
	}
	accessToken, err := h.tk.GenJwt(claims)
	if err != nil {
		return "", 0, err
	}
	return accessToken, int64(time.Until(expireTime).Seconds()), nil
}

func (h Handler) issueIDToken(user *dal.User, client *dal.Client, nonce string) (string, error) {
	now := time.Now()
	expireTime := now.Add(time.Duration(client.AccessTokenAge) * time.Hour)
	return h.tk.GenIDToken(&token.IDTokenClaims{
		Nonce: nonce,
		Name:  user.Name,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: &jwt.NumericDate{Time: expireTime},
			IssuedAt:  &jwt.NumericDate{Time: now},
			Issuer:    h.tokenIssuer(),
			Subject:   user.Uuid,
			Audience:  jwt.Audience{client.ClientId},
		},
	})
}

func (h Handler) tokenIssuer() string {
	return strings.TrimSuffix(strings.TrimSpace(h.conf.OidcIssuer), "/")
}

func (h Handler) oidcIssuer() string {
	return h.tokenIssuer()
}

func (h Handler) oidcLoginURL() string {
	if configured := strings.TrimSpace(h.conf.OidcLoginUrl); configured != "" {
		return configured
	}
	return h.oidcIssuer() + "/login"
}
