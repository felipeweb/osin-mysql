// Package mysql is a osin storage implementation for mysql.
package mysql

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/RangelReale/osin"
	"github.com/ansel1/merry"
	"github.com/felipeweb/gopher-utils"
	// driver for mysql db
	_ "github.com/go-sql-driver/mysql"
)

var schemas = []string{`CREATE TABLE IF NOT EXISTS {prefix}client (
	id           varchar(255) BINARY NOT NULL PRIMARY KEY,
	secret 		 varchar(255) NOT NULL,
	extra 		 varchar(255) NOT NULL,
	redirect_uri varchar(255) NOT NULL
)`, `CREATE TABLE IF NOT EXISTS {prefix}authorize (
	client       varchar(255) BINARY NOT NULL,
	code         varchar(255) BINARY NOT NULL PRIMARY KEY,
	expires_in   int(10) NOT NULL,
	scope        varchar(255) NOT NULL,
	redirect_uri varchar(255) NOT NULL,
	state        varchar(255) NOT NULL,
	extra 		 varchar(255) NOT NULL,
	created_at   timestamp NOT NULL
)`, `CREATE TABLE IF NOT EXISTS {prefix}access (
	client        varchar(255) BINARY NOT NULL,
	authorize     varchar(255) BINARY NOT NULL,
	previous      varchar(255) BINARY NOT NULL,
	access_token  varchar(255) BINARY NOT NULL PRIMARY KEY,
	refresh_token varchar(255) BINARY NOT NULL,
	expires_in    int(10) NOT NULL,
	scope         varchar(255) NOT NULL,
	redirect_uri  varchar(255) NOT NULL,
	extra 		  varchar(255) NOT NULL,
	created_at    timestamp NOT NULL
)`, `CREATE TABLE IF NOT EXISTS {prefix}refresh (
	token         varchar(255) BINARY NOT NULL PRIMARY KEY,
	access        varchar(255) BINARY NOT NULL
)`, `CREATE TABLE IF NOT EXISTS {prefix}expires (
	id 		int(11) NOT NULL PRIMARY KEY AUTO_INCREMENT,
	token		varchar(255) BINARY NOT NULL,
	expires_at	timestamp NOT NULL,
	INDEX expires_index (expires_at),
	INDEX token_expires_index (token)
)`,
}

// Storage implements interface "github.com/RangelReale/osin".Storage and interface "github.com/felipeweb/osin-mysql/storage".Storage
type Storage struct {
	db          *sql.DB
	tablePrefix string
}

// New returns a new mysql storage instance.
func New(db *sql.DB, tablePrefix string) *Storage {
	return &Storage{db, tablePrefix}
}

// CreateSchemas creates the schemata, if they do not exist yet in the database. Returns an error if something went wrong.
func (s *Storage) CreateSchemas() error {
	for k, schema := range schemas {
		schema := strings.Replace(schema, "{prefix}", s.tablePrefix, 4)
		if _, err := s.db.Exec(schema); err != nil {
			log.Printf("Error creating schema %d: %s", k, schema)
			return err
		}
	}
	return nil
}

// Clone the storage if needed. For example, using mgo, you can clone the session with session.Clone
// to avoid concurrent access problems.
// This is to avoid cloning the connection at each method access.
// Can return itself if not a problem.
func (s *Storage) Clone() osin.Storage {
	return s
}

// Close the resources the Storage potentially holds (using Clone for example)
func (s *Storage) Close() {
}

// GetClient loads the client by id
func (s *Storage) GetClient(id string) (osin.Client, error) {
	row := s.db.QueryRow(fmt.Sprintf("SELECT id, secret, redirect_uri, extra FROM %sclient WHERE id=?", s.tablePrefix), id)
	var c osin.DefaultClient
	var extra string

	if err := row.Scan(&c.Id, &c.Secret, &c.RedirectUri, &extra); err == sql.ErrNoRows {
		return nil, osin.ErrNotFound
	} else if err != nil {
		return nil, merry.Wrap(err)
	}
	c.UserData = extra
	return &c, nil
}

// UpdateClient updates the client (identified by it's id) and replaces the values with the values of client.
func (s *Storage) UpdateClient(c osin.Client) error {
	data := gopher_utils.ToStr(c.GetUserData())

	if _, err := s.db.Exec(fmt.Sprintf("UPDATE %sclient SET secret=?, redirect_uri=?, extra=? WHERE id=?", s.tablePrefix), c.GetSecret(), c.GetRedirectUri(), data, c.GetId()); err != nil {
		return merry.Wrap(err)
	}
	return nil
}

// CreateClient stores the client in the database and returns an error, if something went wrong.
func (s *Storage) CreateClient(c osin.Client) error {
	data := gopher_utils.ToStr(c.GetUserData())

	if _, err := s.db.Exec(fmt.Sprintf("INSERT INTO %sclient (id, secret, redirect_uri, extra) VALUES (?, ?, ?, ?)", s.tablePrefix), c.GetId(), c.GetSecret(), c.GetRedirectUri(), data); err != nil {
		return merry.Wrap(err)
	}
	return nil
}

// RemoveClient removes a client (identified by id) from the database. Returns an error if something went wrong.
func (s *Storage) RemoveClient(id string) (err error) {
	if _, err = s.db.Exec(fmt.Sprintf("DELETE FROM %sclient WHERE id=?", s.tablePrefix), id); err != nil {
		return merry.Wrap(err)
	}
	return nil
}

// SaveAuthorize saves authorize data.
func (s *Storage) SaveAuthorize(data *osin.AuthorizeData) (err error) {
	extra := gopher_utils.ToStr(data.UserData)
	if err != nil {
		return err
	}

	if _, err = s.db.Exec(
		fmt.Sprintf("INSERT INTO %sauthorize (client, code, expires_in, scope, redirect_uri, state, created_at, extra) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", s.tablePrefix),
		data.Client.GetId(),
		data.Code,
		data.ExpiresIn,
		data.Scope,
		data.RedirectUri,
		data.State,
		data.CreatedAt,
		extra,
	); err != nil {
		return merry.Wrap(err)
	}
	if err = s.AddExpireAtData(data.Code, data.ExpireAt()); err != nil {
		return merry.Wrap(err)
	}
	return nil
}

// LoadAuthorize looks up AuthorizeData by a code.
// Client information MUST be loaded together.
// Optionally can return error if expired.
func (s *Storage) LoadAuthorize(code string) (*osin.AuthorizeData, error) {
	var data osin.AuthorizeData
	var extra string
	var cid string
	if err := s.db.QueryRow(fmt.Sprintf("SELECT client, code, expires_in, scope, redirect_uri, state, created_at, extra FROM %sauthorize WHERE code=? LIMIT 1", s.tablePrefix), code).Scan(&cid, &data.Code, &data.ExpiresIn, &data.Scope, &data.RedirectUri, &data.State, &data.CreatedAt, &extra); err == sql.ErrNoRows {
		return nil, osin.ErrNotFound
	} else if err != nil {
		return nil, merry.Wrap(err)
	}
	data.UserData = extra

	c, err := s.GetClient(cid)
	if err != nil {
		return nil, err
	}

	if data.ExpireAt().Before(time.Now()) {
		return nil, merry.Errorf("Token expired at %s.", data.ExpireAt().String())
	}

	data.Client = c
	return &data, nil
}

// RemoveAuthorize revokes or deletes the authorization code.
func (s *Storage) RemoveAuthorize(code string) (err error) {
	if _, err = s.db.Exec(fmt.Sprintf("DELETE FROM %sauthorize WHERE code=?", s.tablePrefix), code); err != nil {
		return merry.Wrap(err)
	}
	if err = s.RemoveExpireAtData(code); err != nil {
		return merry.Wrap(err)
	}
	return nil
}

// SaveAccess writes AccessData.
// If RefreshToken is not blank, it must save in a way that can be loaded using LoadRefresh.
func (s *Storage) SaveAccess(data *osin.AccessData) (err error) {
	prev := ""
	authorizeData := &osin.AuthorizeData{}

	if data.AccessData != nil {
		prev = data.AccessData.AccessToken
	}

	if data.AuthorizeData != nil {
		authorizeData = data.AuthorizeData
	}

	extra := gopher_utils.ToStr(data.UserData)

	tx, err := s.db.Begin()
	if err != nil {
		return merry.Wrap(err)
	}

	if data.RefreshToken != "" {
		if err := s.saveRefresh(tx, data.RefreshToken, data.AccessToken); err != nil {
			return err
		}
	}

	if data.Client == nil {
		return merry.New("data.Client must not be nil")
	}

	_, err = tx.Exec(fmt.Sprintf("INSERT INTO %saccess (client, authorize, previous, access_token, refresh_token, expires_in, scope, redirect_uri, created_at, extra) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", s.tablePrefix), data.Client.GetId(), authorizeData.Code, prev, data.AccessToken, data.RefreshToken, data.ExpiresIn, data.Scope, data.RedirectUri, data.CreatedAt, extra)
	if err != nil {
		if rbe := tx.Rollback(); rbe != nil {
			return merry.Wrap(rbe)
		}
		return merry.Wrap(err)
	}

	if err = s.AddExpireAtData(data.AccessToken, data.ExpireAt()); err != nil {
		return merry.Wrap(err)
	}
	if err = tx.Commit(); err != nil {
		return merry.Wrap(err)
	}

	return nil
}

// LoadAccess retrieves access data by token. Client information MUST be loaded together.
// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
// Optionally can return error if expired.
func (s *Storage) LoadAccess(code string) (*osin.AccessData, error) {
	var extra, cid, prevAccessToken, authorizeCode string
	var result osin.AccessData

	if err := s.db.QueryRow(
		fmt.Sprintf("SELECT client, authorize, previous, access_token, refresh_token, expires_in, scope, redirect_uri, created_at, extra FROM %saccess WHERE access_token=? LIMIT 1", s.tablePrefix),
		code,
	).Scan(
		&cid,
		&authorizeCode,
		&prevAccessToken,
		&result.AccessToken,
		&result.RefreshToken,
		&result.ExpiresIn,
		&result.Scope,
		&result.RedirectUri,
		&result.CreatedAt,
		&extra,
	); err == sql.ErrNoRows {
		return nil, osin.ErrNotFound
	} else if err != nil {
		return nil, merry.Wrap(err)
	}

	result.UserData = extra
	client, err := s.GetClient(cid)
	if err != nil {
		return nil, err
	}

	result.Client = client
	result.AuthorizeData, _ = s.LoadAuthorize(authorizeCode)
	prevAccess, _ := s.LoadAccess(prevAccessToken)
	result.AccessData = prevAccess
	return &result, nil
}

// RemoveAccess revokes or deletes an AccessData.
func (s *Storage) RemoveAccess(code string) (err error) {
	if _, err = s.db.Exec(fmt.Sprintf("DELETE FROM %saccess WHERE access_token=?", s.tablePrefix), code); err != nil {
		return merry.Wrap(err)
	}
	if err = s.RemoveExpireAtData(code); err != nil {
		return merry.Wrap(err)
	}
	return nil
}

// LoadRefresh retrieves refresh AccessData. Client information MUST be loaded together.
// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
// Optionally can return error if expired.
func (s *Storage) LoadRefresh(code string) (*osin.AccessData, error) {
	row := s.db.QueryRow(fmt.Sprintf("SELECT access FROM %srefresh WHERE token=? LIMIT 1", s.tablePrefix), code)
	var access string
	if err := row.Scan(&access); err == sql.ErrNoRows {
		return nil, osin.ErrNotFound
	} else if err != nil {
		return nil, merry.Wrap(err)
	}
	return s.LoadAccess(access)
}

// RemoveRefresh revokes or deletes refresh AccessData.
func (s *Storage) RemoveRefresh(code string) error {
	_, err := s.db.Exec(fmt.Sprintf("DELETE FROM %srefresh WHERE token=?", s.tablePrefix), code)
	if err != nil {
		return merry.Wrap(err)
	}
	return nil
}

// CreateClientWithInformation Makes easy to create a osin.DefaultClient
func (s *Storage) CreateClientWithInformation(id string, secret string, redirectURI string, userData interface{}) osin.Client {
	return &osin.DefaultClient{
		Id:          id,
		Secret:      secret,
		RedirectUri: redirectURI,
		UserData:    userData,
	}
}

func (s *Storage) saveRefresh(tx *sql.Tx, refresh, access string) (err error) {
	_, err = tx.Exec(fmt.Sprintf("INSERT INTO %srefresh (token, access) VALUES (?, ?)", s.tablePrefix), refresh, access)
	if err != nil {
		if rbe := tx.Rollback(); rbe != nil {
			return merry.Wrap(rbe)
		}
		return merry.Wrap(err)
	}
	return nil
}

// AddExpireAtData add info in expires table
func (s *Storage) AddExpireAtData(code string, expireAt time.Time) error {
	if _, err := s.db.Exec(
		fmt.Sprintf("INSERT INTO %sexpires(token, expires_at) VALUES(?, ?)", s.tablePrefix),
		code,
		expireAt,
	); err != nil {
		return merry.Wrap(err)
	}

	return nil
}

// RemoveExpireAtData remove info in expires table
func (s *Storage) RemoveExpireAtData(code string) error {
	if _, err := s.db.Exec(
		fmt.Sprintf("DELETE FROM %sexpires WHERE token=?", s.tablePrefix),
		code,
	); err != nil {
		return merry.Wrap(err)
	}
	return nil
}
