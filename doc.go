/*Package mysql is a storage backend for osin oauth2. Additional to implementing the osin.Storage interface, the github.com/felipeweb/osin-mysql/storage.Storage interface defines new methods:

	// CreateClient stores the client in the database and returns an error, if something went wrong.
	CreateClient(client osin.Client) error

	// UpdateClient updates the client (identified by its id) and replaces the values with the values of client.
	// Returns an error if something went wrong.
	UpdateClient(client osin.Client) error

	// RemoveClient removes a client (identified by id) from the database. Returns an error if something went wrong.
	RemoveClient(id string) error
Encrypt your tokens

Unfortunately, the osin library offers little capabilities for storing credentials like access or refresh tokens in a hashed or encrypted way. An attacker could gain access to your database through various attack vectors, steal these tokens and gain, for example, administrative access to your application.

Please be aware, that this library stores all data as-is and does not perform any sort of encryption or hashing.

Usage

First, install this library with go get "github.com/felipeweb/osin-mysql".

	import (
	    "database/sql"
	    _ "github.com/go-sql-driver/mysql"

	    "github.com/felipeweb/osin-mysql"
	    "github.com/RangelReale/osin"
	)

	func main() {
	    url := "user:password@tcp(host:3306)/dbname?parseTime=true"
	    db, err := sql.Open("mysql", url)
	    if err != nil {
		return nil, err
	    }

	    store := mysql.New(db,"osin_")
	    store.CreateSchemas()
	    server := osin.NewServer(osin.NewServerConfig(), store)

	    // See the osin documentation for more information
	    // e.g.: server.HandleAuthorizeRequest(resp, r)
	}
Limitations

TL;DR AuthorizeData's Client's and AccessData's UserData field must be string due to language restrictions or an error will be thrown.

In osin, Client, AuthorizeData and AccessData have a UserData property of type interface{}. This does not work well with SQL, because it is not possible to gob decode or unmarshall the data back, since the concrete type is not known. Because osin's storage interface does not support setting the UserData type, this library tries to convert UserData to string and return it as such. With this, you could for example gob encode (use e.g. base64 encode for SQL storage type compatibility) the data before passing it to e.g. FinishAccessRequest and decode it when needed.
*/
package mysql
