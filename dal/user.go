package dal

import (
	"database/sql"
	"errors"
)

type IUser interface {
	Init() error
	Insert(user *User) error
	SelectById(id int64) (*User, error)
	SelectByUuid(uuid string) (*User, error)
	SelectByName(name string) (*User, error)
	DeleteById(id int64) error
}

type User struct {
	db       *sql.DB
	Id       int64
	Uuid     string
	Name     string
	Password string
	Deleted  bool
}

func (u User) Init() error {
	if _, err := u.db.Exec(`
	CREATE TABLE IF NOT EXISTS users (
	    id INTEGER PRIMARY KEY AUTOINCREMENT,
	    uuid TEXT NOT NULL UNIQUE,
	    name TEXT NOT NULL UNIQUE,
	    password TEXT NOT NULL,
		deleted INTEGER NOT NULL DEFAULT 0
	);`); err != nil {
		return err
	}
	rows, err := u.db.Query(`SELECT * FROM sqlite_master WHERE type = "index" AND tbl_name = "users" AND name = "idx_uuid";`)
	if err != nil {
		return err
	}
	if !rows.Next() {
		if _, err = u.db.Exec(`CREATE UNIQUE INDEX idx_uuid ON users(uuid);`); err != nil {
			return err
		}
	}
	return rows.Close()
}

func (u User) Insert(user *User) error {
	_, err := u.db.Exec("INSERT INTO users (uuid, name, password) VALUES (?, ?, ?);", user.Uuid, user.Name, user.Password)
	return err
}

func (u User) SelectById(id int64) (user *User, err error) {
	rows, err := u.db.Query("SELECT * FROM users WHERE (id = ? AND deleted = 0);", id)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, rows.Close())
	}()
	user = new(User)
	if rows.Next() {
		if err := rows.Scan(&user.Id, &user.Uuid, &user.Name, &user.Password, &user.Deleted); err != nil {
			return nil, err
		}
	} else {
		return nil, nil
	}
	return user, err
}

func (u User) SelectByUuid(uuid string) (user *User, err error) {
	rows, err := u.db.Query("SELECT * FROM users WHERE (uuid = ? AND deleted = 0);", uuid)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, rows.Close())
	}()
	user = new(User)
	if rows.Next() {
		if err := rows.Scan(&user.Id, &user.Uuid, &user.Name, &user.Password, &user.Deleted); err != nil {
			return nil, err
		}
	} else {
		return nil, nil
	}
	return user, err
}

func (u User) SelectByName(name string) (user *User, err error) {
	rows, err := u.db.Query("SELECT * FROM users WHERE (name = ? AND deleted = 0);", name)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, rows.Close())
	}()
	user = new(User)
	if rows.Next() {
		if err := rows.Scan(&user.Id, &user.Uuid, &user.Name, &user.Password, &user.Deleted); err != nil {
			return nil, err
		}
	} else {
		return nil, nil
	}
	return user, err
}

func (u User) DeleteById(id int64) error {
	_, err := u.db.Exec("UPDATE users SET deleted = 1 WHERE id = ?;", id)
	return err
}
