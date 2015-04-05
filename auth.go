// Authenticate interfaces for Authatron.
package authatron

import (
	"encoding/gob"
	"errors"
	"fmt"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"net/http"
)

type AuthenticateService interface {
	UserStore
	Authenticator
}

func NewAuthenticateService() AuthenticateService {
	return &struct {
		fakeAuthenticator
		cookieUserStore
	}{
		fakeAuthenticator{"password"},
		cookieUserStore{sessions.NewCookieStore([]byte("secret")), "session-1"},
	}
}

// UserStore is an interface for storing/retrieving user details
type UserStore interface {
	// Store the provided user in the session provided by request.
	StoreUserForRequest(w http.ResponseWriter, r *http.Request, user User) error

	// Retrieve the users details for this request, if no user is logged
	// in the User returned is nil
	RetrieveUserFromRequest(r *http.Request) (User, error)

	// Retrieve the users details from the provided auth key, if no user is
	// logged in the User return is nil
	RetrieveUserFromAuthKey(authKey string) (User, error)

	// ForgetUserForRequest removes the details of the current logged in
	// user for this session
	ForgetUserForRequest(w http.ResponseWriter, r *http.Request) error
}

type cookieUserStore struct {
	store       *sessions.CookieStore
	sessionName string
}

func (cus *cookieUserStore) StoreUserForRequest(w http.ResponseWriter, r *http.Request, user User) error {
	session, _ := cus.store.Get(r, cus.sessionName)
	session.Values["user"] = user
	return session.Save(r, w)
}

func (cus *cookieUserStore) RetrieveUserFromRequest(r *http.Request) (User, error) {
	session, _ := cus.store.Get(r, cus.sessionName)
	switch user := session.Values["user"].(type) {
	case User:
		return user, nil
	default:
		return nil, nil
	}
}

func (cus *cookieUserStore) RetrieveUserFromAuthKey(authKey string) (User, error) {
	session := sessions.NewSession(cus.store, cus.sessionName)
	opts := *cus.store.Options
	session.Options = &opts
	session.IsNew = true
	err := securecookie.DecodeMulti(cus.sessionName, authKey, &session.Values, cus.store.Codecs...)
	if err == nil {
		session.IsNew = false
	}
	user, exists := session.Values["user"]
	if !exists {
		return nil, nil
	}
	switch u := user.(type) {
	case User:
		return u, nil
	default:
		return nil, errors.New("User was not a string")
	}
}

func (cus *cookieUserStore) ForgetUserForRequest(w http.ResponseWriter, r *http.Request) error {
	session, _ := cus.store.Get(r, cus.sessionName)
	delete(session.Values, "user")
	fmt.Printf("Session: %s\n", session.Values)
	return session.Save(r, w)
}

// Authenticator interface for any authentication backend this wishes to authenticate
// a user
type Authenticator interface {
	// Authenticate checks the provided username and password returning
	// a User if successful
	Authenticate(username, password string) (User, error)
}

// fakeAuthenticator is an in memory authenticator with one shared password.
type fakeAuthenticator struct {
	fakePassword string
}

func (fa fakeAuthenticator) Authenticate(username, password string) (User, error) {
	if password == fa.fakePassword {
		return &fakeUser{username}, nil
	}
	return nil, errors.New("Incorrect password")
}

// Interface that describes a logged in user.
type User interface {
	UserID() string
}

// fakeUser is a User struct fulfilling the User interface returned by the
// fakeAuthenticator
type fakeUser struct {
	FakeUserID string
}

func (cu fakeUser) UserID() string {
	return cu.FakeUserID
}

func init() {
	// Register this struct as we're saving using an interface so this needs to
	// be explicitly set.
	gob.Register(fakeUser{})
}
