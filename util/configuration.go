package util

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
)

type Configuration struct {
	HttpAddress             string   `json:"httpAddress"`
	AllowedOrigins          []string `json:"allowedOrigins"`
	SecureCookies           bool     `json:"secureCookies"`
	OidcIssuer              string   `json:"oidcIssuer"`
	OidcLoginUrl            string   `json:"oidcLoginUrl"`
	InvitationCode          string   `json:"invitationCode"`
	AdminPassword           string   `json:"adminPassword"`
	AuthorizationCodeLength int      `json:"authorizationCodeLength"`
	RefreshTokenLength      int      `json:"refreshTokenLength"`
	PasswordMinLength       int      `json:"passwordMinLength"`
	DbPath                  string   `json:"dbPath"`
	LogFilePath             string   `json:"logFilePath"`
	RsaPrivateKeyPath       string   `json:"rsaPrivateKeyPath"`
}

func (c *Configuration) Init() error {
	confJson, err := os.ReadFile("./conf.json")
	if err != nil {
		return err
	}
	if err := json.Unmarshal(confJson, &c); err != nil {
		return err
	}
	if strings.TrimSpace(c.OidcIssuer) == "" {
		return errors.New("oidcIssuer is required")
	}
	c.OidcIssuer = strings.TrimSuffix(strings.TrimSpace(c.OidcIssuer), "/")
	return nil
}
