package token

import (
	"crypto/rsa"

	"github.com/undefinednil/myoauth/util"
)

type Token struct {
	conf          *util.Configuration
	logger        *util.Logger
	rsaPrivateKey *rsa.PrivateKey
}
