package handler

import (
	"net/http"
	"strings"
	"time"

	"github.com/cristalhq/jwt/v5"
)

// isAccessTokenRevoked reports whether an access token jti has been revoked.
// The in-memory denylist is a fast cache in front of the durable DB store
// (FIX F9). It fails closed: a DB error is reported as revoked so callers
// surface a 401 rather than admitting a token whose durable state is unknown.
func (h Handler) isAccessTokenRevoked(jti string) (bool, error) {
	if jti == "" {
		return false, nil
	}
	if h.denylist != nil && h.denylist.Contains(jti) {
		return true, nil
	}
	revoked, err := h.db.TokenStore.IsRevoked(jti)
	if err != nil {
		h.logger.Println("check revoked token error:", err)
		return true, err
	}
	return revoked, nil
}

// oidcRevoke implements RFC 7009 token revocation. Per the RFC it always returns
// 200 for an unknown/invalid token; only client authentication (401) and a
// missing token (400) are errors. A client can only revoke tokens it owns
// (FIX F2).
func (h Handler) oidcRevoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		responseOIDCError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
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
	tokenValue := strings.TrimSpace(r.PostForm.Get("token"))
	if tokenValue == "" {
		responseOIDCError(w, http.StatusBadRequest, "invalid_request", "token is required")
		return
	}

	if refreshToken, err := h.db.RefreshTokens.SelectByToken(tokenValue); err != nil {
		responseInternalError(w, h.logger, err)
		return
	} else if refreshToken != nil {
		// Only the owning client may revoke a refresh token; anything else is a
		// no-op (FIX F2).
		if refreshToken.ClientId == client.Id {
			if err := h.db.RefreshTokens.DeleteById(refreshToken.Id); err != nil {
				responseInternalError(w, h.logger, err)
				return
			}
		}
	}

	// Access token revocation: require an access token whose audience contains
	// the authenticated client (FIX F2, FIX F3), and persist the revocation so
	// it survives a restart (FIX F9).
	if claims, ok, _ := h.tk.ParseAndVerifyAccessJwt(tokenValue, client.ClientId); ok && claims.ID != "" && claims.ExpiresAt != nil {
		h.denylist.Add(claims.ID, claims.ExpiresAt.Time)
		if err := h.db.TokenStore.Revoke(claims.ID, claims.ExpiresAt.Time); err != nil {
			responseInternalError(w, h.logger, err)
			return
		}
	}

	responseOk(w)
}

type introspectResp struct {
	Active    bool         `json:"active"`
	Scope     string       `json:"scope,omitempty"`
	ClientId  string       `json:"client_id,omitempty"`
	TokenType string       `json:"token_type,omitempty"`
	Exp       int64        `json:"exp,omitempty"`
	Iat       int64        `json:"iat,omitempty"`
	Sub       string       `json:"sub,omitempty"`
	Aud       jwt.Audience `json:"aud,omitempty"`
	Iss       string       `json:"iss,omitempty"`
}

// oidcIntrospect implements RFC 7662 token introspection. The raw token is never
// echoed back, and a client can only introspect tokens it owns (FIX F2, F3).
func (h Handler) oidcIntrospect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		responseOIDCError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
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
	tokenValue := strings.TrimSpace(r.PostForm.Get("token"))
	if tokenValue == "" {
		responseOIDCError(w, http.StatusBadRequest, "invalid_request", "token is required")
		return
	}

	// Only an access token addressed to this client is introspectable. An ID
	// token or a token for another client falls through to active:false.
	if claims, ok, _ := h.tk.ParseAndVerifyAccessJwt(tokenValue, client.ClientId); ok {
		// A denylist/DB error is fail-closed: report inactive rather than
		// claiming a token is live when its revocation state is unknown.
		if revoked, err := h.isAccessTokenRevoked(claims.ID); err != nil || revoked {
			responseJson(w, introspectResp{Active: false})
			return
		}
		// The token is only active while its subject still exists, consistent
		// with /userinfo.
		if user, err := h.db.Users.SelectByUuid(claims.Subject); err != nil {
			responseInternalError(w, h.logger, err)
			return
		} else if user == nil {
			responseJson(w, introspectResp{Active: false})
			return
		}
		resp := introspectResp{
			Active:    true,
			Scope:     claims.Scope,
			TokenType: "Bearer",
			Sub:       claims.Subject,
			Iss:       claims.Issuer,
			Aud:       claims.Audience,
		}
		if len(claims.Audience) > 0 {
			resp.ClientId = claims.Audience[0]
		}
		if claims.ExpiresAt != nil {
			resp.Exp = claims.ExpiresAt.Unix()
		}
		if claims.IssuedAt != nil {
			resp.Iat = claims.IssuedAt.Unix()
		}
		responseJson(w, resp)
		return
	}

	refreshToken, err := h.db.RefreshTokens.SelectByToken(tokenValue)
	if err != nil {
		responseInternalError(w, h.logger, err)
		return
	}
	// Never leak another client's refresh token details (FIX F2).
	if refreshToken == nil || refreshToken.ClientId != client.Id {
		responseJson(w, introspectResp{Active: false})
		return
	}
	if refreshToken.ExpireTime != nil && refreshToken.ExpireTime.Before(time.Now()) {
		responseJson(w, introspectResp{Active: false})
		return
	}

	resp := introspectResp{Active: true, Scope: refreshToken.Scope}
	if client, err := h.db.Clients.SelectById(refreshToken.ClientId); err != nil {
		responseInternalError(w, h.logger, err)
		return
	} else if client != nil {
		resp.ClientId = client.ClientId
	}
	if user, err := h.db.Users.SelectById(refreshToken.UserId); err != nil {
		responseInternalError(w, h.logger, err)
		return
	} else if user != nil {
		resp.Sub = user.Uuid
	}
	if refreshToken.ExpireTime != nil {
		resp.Exp = refreshToken.ExpireTime.Unix()
	}
	responseJson(w, resp)
}
