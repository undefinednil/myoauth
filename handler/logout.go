package handler

import (
	"net/http"
	"net/url"

	"github.com/zenpk/my-oauth/dal"
	"github.com/zenpk/my-oauth/token"
)

// oidcLogout implements RP-initiated logout. The client is resolved from
// client_id, or derived from a valid id_token_hint audience. A valid hint also
// revokes the user's refresh tokens for that client.
func (h Handler) oidcLogout(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	clientId := query.Get("client_id")
	idTokenHint := query.Get("id_token_hint")
	postLogoutRedirectURI := query.Get("post_logout_redirect_uri")
	state := query.Get("state")

	// `/logout` is both the OIDC end_session_endpoint and the SPA route. A
	// request without any logout parameter is a plain SPA navigation, so serve
	// the SPA instead of redirecting (which would loop back to this handler).
	if clientId == "" && idTokenHint == "" && postLogoutRedirectURI == "" {
		h.webHandler().ServeHTTP(w, r)
		return
	}

	var client *dal.Client
	if clientId != "" {
		found, err := h.db.Clients.SelectByClientId(clientId)
		if err != nil {
			responseInternalError(w, h.logger, err)
			return
		}
		client = found
	}

	var claims *token.AccessTokenClaims
	if idTokenHint != "" {
		// A malformed/non-ID hint is a client error, not a server error (FIX F8),
		// and it must never be used to revoke sessions. An expired-but-validly-
		// signed ID token is accepted as the logout hint (OIDC recommends it) but
		// only here: /userinfo, /introspect and /revoke keep enforcing exp.
		parsed, ok, err := h.tk.ParseAndVerifyIDJwtAllowExpired(idTokenHint)
		if err != nil || !ok {
			responseOIDCError(w, http.StatusBadRequest, "invalid_request", "invalid id_token_hint")
			return
		}
		// If both are present, the hint must be addressed to the client
		// (FIX F5); otherwise it cannot be trusted to identify the session.
		if client != nil {
			if !parsed.IsForAudience(client.ClientId) {
				responseOIDCError(w, http.StatusBadRequest, "invalid_request", "id_token_hint audience does not match client_id")
				return
			}
		} else if len(parsed.Audience) > 0 {
			found, err := h.db.Clients.SelectByClientId(parsed.Audience[0])
			if err != nil {
				responseInternalError(w, h.logger, err)
				return
			}
			client = found
		}
		claims = parsed
	}

	if client != nil && claims != nil && claims.Subject != "" {
		user, err := h.db.Users.SelectByUuid(claims.Subject)
		if err != nil {
			responseInternalError(w, h.logger, err)
			return
		}
		if user != nil {
			if err := h.sv.RevokeUserSessions(user.Id, client.Id); err != nil {
				responseInternalError(w, h.logger, err)
				return
			}
			// A revoke that only drops refresh tokens would leave outstanding
			// access tokens valid; invalidate them durably as well.
			if err := h.db.TokenStore.RevokeAccessTokensByUserAndClient(user.Id, client.Id); err != nil {
				responseInternalError(w, h.logger, err)
				return
			}
		}
	}

	if postLogoutRedirectURI != "" && client != nil && isRedirectAllowed(client.Redirects, postLogoutRedirectURI) {
		if target, err := url.Parse(postLogoutRedirectURI); err == nil {
			if state != "" {
				q := target.Query()
				q.Set("state", state)
				target.RawQuery = q.Encode()
			}
			http.Redirect(w, r, target.String(), http.StatusFound)
			return
		}
	}

	target := "/logout"
	if state != "" {
		target += "?state=" + url.QueryEscape(state)
	}
	http.Redirect(w, r, target, http.StatusFound)
}
