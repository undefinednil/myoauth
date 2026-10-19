package service

import (
	"context"
	"time"

	"github.com/undefinednil/myoauth/dal"
	"github.com/undefinednil/myoauth/util"
)

func (s *Service) GenAndInsertRefreshToken(ctx context.Context, client *dal.Client, user *dal.User, scope string) (string, error) {
	// Each login/refresh starts its own rotating chain so multiple devices can
	// stay signed in; rotation deletes only the previous token by id. The
	// granted scope is persisted so it cannot be escalated later (FIX F4).
	refreshToken, err := util.RandString(s.conf.RefreshTokenLength)
	if err != nil {
		return "", err
	}
	expireTime := time.Now().Add(time.Duration(client.RefreshTokenAge) * time.Hour)
	if err := s.db.RefreshTokens.Insert(ctx, &dal.RefreshToken{
		Token:      refreshToken,
		ClientId:   client.Id,
		UserId:     user.Id,
		ExpireTime: &expireTime,
		Scope:      scope,
	}); err != nil {
		return "", err
	}
	return refreshToken, nil
}

// RevokeUserSessions deletes every refresh token a user holds for a client.
func (s *Service) RevokeUserSessions(ctx context.Context, userId, clientId int64) error {
	return s.db.RefreshTokens.DeleteByUserAndClient(ctx, userId, clientId)
}
