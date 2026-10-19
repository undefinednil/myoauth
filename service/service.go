package service

import (
	"github.com/zenpk/my-oauth/dal"
	"github.com/zenpk/my-oauth/util"
)

type IService interface{}

type Service struct {
	conf *util.Configuration
	db   *dal.Database
}

func (s *Service) Init(conf *util.Configuration, db *dal.Database) {
	s.conf = conf
	s.db = db
}
