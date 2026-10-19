package service

import (
	"github.com/undefinednil/myoauth/dal"
	"github.com/undefinednil/myoauth/util"
)

type Service struct {
	conf *util.Configuration
	db   *dal.Database
}

func (s *Service) Init(conf *util.Configuration, db *dal.Database) {
	s.conf = conf
	s.db = db
}
