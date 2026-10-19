package token

import (
	"crypto/rsa"

	"github.com/zenpk/my-oauth/util"
)

type IToken interface{}

type Token struct {
	conf          *util.Configuration
	logger        *util.Logger
	rsaPrivateKey *rsa.PrivateKey
}
