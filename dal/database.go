package dal

import (
	"database/sql"

	_ "github.com/glebarez/go-sqlite"
	"github.com/zenpk/my-oauth/util"
)

type Database struct {
	instance      *sql.DB
	Users         IUser
	RefreshTokens IRefreshToken
	Clients       IClient
}

func (d *Database) Init(conf *util.Configuration) error {
	sqlite, err := sql.Open("sqlite", conf.DbPath)
	if err != nil {
		return err
	}
	sqlite.SetMaxOpenConns(1)
	if _, err := sqlite.Exec("PRAGMA journal_mode=WAL;"); err != nil {
		return err
	}
	if _, err := sqlite.Exec("PRAGMA foreign_keys=ON;"); err != nil {
		return err
	}
	users := &User{db: sqlite}
	if err := users.Init(); err != nil {
		return err
	}
	refreshTokens := &RefreshToken{db: sqlite}
	if err := refreshTokens.Init(); err != nil {
		return err
	}
	clients := &Client{db: sqlite}
	if err := clients.Init(); err != nil {
		return err
	}
	d.instance = sqlite
	d.Users = users
	d.RefreshTokens = refreshTokens
	d.Clients = clients
	return nil
}

func (d *Database) Close() error {
	return d.instance.Close()
}
