package dal

import (
	"context"
	"database/sql"
	"errors"
)

type IUser interface {
	Insert(ctx context.Context, user *User) error
	SelectById(ctx context.Context, id int64) (*User, error)
	SelectByUuid(ctx context.Context, uuid string) (*User, error)
	SelectByName(ctx context.Context, name string) (*User, error)
	DeleteById(ctx context.Context, id int64) error
}

type User struct {
	db       *sql.DB
	Id       int64
	Uuid     string
	Name     string
	Password string
	Deleted  bool
}

func (u User) Insert(ctx context.Context, user *User) error {
	_, err := u.db.ExecContext(ctx, "INSERT INTO users (uuid, name, password) VALUES (?, ?, ?);", user.Uuid, user.Name, user.Password)
	return err
}

func (u User) SelectById(ctx context.Context, id int64) (user *User, err error) {
	rows, err := u.db.QueryContext(ctx, "SELECT * FROM users WHERE (id = ? AND deleted = 0);", id)
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

func (u User) SelectByUuid(ctx context.Context, uuid string) (user *User, err error) {
	rows, err := u.db.QueryContext(ctx, "SELECT * FROM users WHERE (uuid = ? AND deleted = 0);", uuid)
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

func (u User) SelectByName(ctx context.Context, name string) (user *User, err error) {
	rows, err := u.db.QueryContext(ctx, "SELECT * FROM users WHERE (name = ? AND deleted = 0);", name)
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

func (u User) DeleteById(ctx context.Context, id int64) error {
	_, err := u.db.ExecContext(ctx, "UPDATE users SET deleted = 1 WHERE id = ?;", id)
	return err
}
