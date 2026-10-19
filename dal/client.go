package dal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// ErrClientExists reports that a client_id is already used by a non-deleted
// client. Handlers should map it to HTTP 409.
var ErrClientExists = errors.New("client already exists")

type IClient interface {
	Insert(ctx context.Context, client *Client) error
	SelectById(ctx context.Context, id int64) (*Client, error)
	SelectByClientId(ctx context.Context, clientId string) (*Client, error)
	SelectAll(ctx context.Context) ([]*Client, error)
	UpdateById(ctx context.Context, client *Client) error
	DeleteById(ctx context.Context, id int64) error
}

type Client struct {
	db              *sql.DB
	Id              int64  `json:"id"`
	ClientId        string `json:"clientId"`
	Secret          string `json:"secret"`
	Redirects       string `json:"redirects"`
	AccessTokenAge  int64  `json:"accessTokenAge"`
	RefreshTokenAge int64  `json:"refreshTokenAge"`
	Deleted         bool
}

func (c Client) Insert(ctx context.Context, client *Client) error {
	if _, err := c.db.ExecContext(ctx, "INSERT INTO clients (client_id, secret, redirects, access_token_age, refresh_token_age) VALUES (?, ?, ?, ?, ?);",
		client.ClientId, client.Secret, client.Redirects, client.AccessTokenAge, client.RefreshTokenAge); err != nil {
		if IsUniqueConstraintError(err) {
			return fmt.Errorf("%w: client_id %q", ErrClientExists, client.ClientId)
		}
		return err
	}
	return nil
}

// IsUniqueConstraintError reports whether err is a SQLite UNIQUE constraint
// violation. glebarez/go-sqlite surfaces those as "constraint failed: UNIQUE
// constraint failed: ...", so matching the text is how duplicates are detected
// without relying on a check-then-insert race.
func IsUniqueConstraintError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

func (c Client) SelectById(ctx context.Context, id int64) (client *Client, err error) {
	rows, err := c.db.QueryContext(ctx, "SELECT * FROM clients WHERE (id = ? AND deleted = 0);", id)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, rows.Close())
	}()
	client = new(Client)
	if rows.Next() {
		if err := rows.Scan(
			&client.Id, &client.ClientId, &client.Secret, &client.Redirects, &client.AccessTokenAge,
			&client.RefreshTokenAge, &client.Deleted); err != nil {
			return nil, err
		}
	} else {
		return nil, nil
	}
	return client, err
}

func (c Client) SelectByClientId(ctx context.Context, clientId string) (client *Client, err error) {
	rows, err := c.db.QueryContext(ctx, "SELECT * FROM clients WHERE (client_id = ? AND deleted = 0);", clientId)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, rows.Close())
	}()
	client = new(Client)
	if rows.Next() {
		if err := rows.Scan(
			&client.Id, &client.ClientId, &client.Secret, &client.Redirects, &client.AccessTokenAge,
			&client.RefreshTokenAge, &client.Deleted); err != nil {
			return nil, err
		}
	} else {
		return nil, nil
	}
	return client, err
}

func (c Client) SelectAll(ctx context.Context) (clients []*Client, err error) {
	rows, err := c.db.QueryContext(ctx, "SELECT * FROM clients WHERE deleted = 0;")
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, rows.Close())
	}()
	clients = make([]*Client, 0)
	for rows.Next() {
		client := new(Client)
		if err := rows.Scan(
			&client.Id, &client.ClientId, &client.Secret, &client.Redirects, &client.AccessTokenAge,
			&client.RefreshTokenAge, &client.Deleted); err != nil {
			return nil, err
		}
		clients = append(clients, client)
	}
	return clients, err
}

func (c Client) UpdateById(ctx context.Context, client *Client) error {
	if _, err := c.db.ExecContext(ctx, "UPDATE clients SET client_id = ?, secret = ?, redirects = ?, access_token_age = ?, refresh_token_age = ? WHERE id = ? AND deleted = 0;",
		client.ClientId, client.Secret, client.Redirects, client.AccessTokenAge, client.RefreshTokenAge, client.Id); err != nil {
		if IsUniqueConstraintError(err) {
			return fmt.Errorf("%w: client_id %q", ErrClientExists, client.ClientId)
		}
		return err
	}
	return nil
}

func (c Client) DeleteById(ctx context.Context, id int64) error {
	_, err := c.db.ExecContext(ctx, "UPDATE clients SET deleted = 1 WHERE id = ?;", id)
	return err
}
