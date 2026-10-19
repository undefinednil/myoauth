package service

import (
	"time"

	"github.com/zenpk/my-oauth/dal"
	"github.com/zenpk/my-oauth/util"
)

func (s *Service) GenAndInsertRefreshToken(client *dal.Client, user *dal.User) (string, error) {
	// invalidate old refresh tokens for this user+client pair
	if err := s.db.RefreshTokens.DeleteByUserAndClient(user.Id, client.Id); err != nil {
		return "", err
	}
	refreshToken, err := util.RandString(s.conf.RefreshTokenLength)
	if err != nil {
		return "", err
	}
	expireTime := time.Now().Add(time.Duration(client.RefreshTokenAge) * time.Hour)
	if err := s.db.RefreshTokens.Insert(&dal.RefreshToken{
		Token:      refreshToken,
		ClientId:   client.Id,
		UserId:     user.Id,
		ExpireTime: &expireTime,
	}); err != nil {
		return "", err
	}
	return refreshToken, nil
}
