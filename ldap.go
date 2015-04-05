// LDAP authentication implementation for Authatron

package authatron

import (
	"errors"
	"fmt"
	"github.com/mavricknz/ldap"
)

// ldapAuthenticator implements the Authenticator interface while
// authenticating users against an LDAP interface
type ldapAuthenticator struct {
	host           string
	port           uint16
	bindDN         string
	bindpw         string
	baseDN         string
	filterTemplate string
}

// An individual authentication request to check a username and password
type ldapAuthenticationRequest struct {
	conn *ldap.LDAPConnection
	err  error
}

// NewLDAPAuthenticatorFromConfig creates a new Authenticator from the
// provided LDAPAuthConfig
func NewLDAPAuthenticatorFromConfig(config LDAPAuthConfig) ldapAuthenticator {
	return ldapAuthenticator{
		host:           config.Host,
		port:           config.Port,
		bindDN:         config.BindDN,
		bindpw:         config.BindPassword,
		baseDN:         config.BaseDN,
		filterTemplate: config.UserNameLookupFilter,
	}
}

// connect this ldapAuthenticationRequest to the ldap server
func (lr *ldapAuthenticationRequest) connect(host string, port uint16) {
	lr.conn = ldap.NewLDAPConnection(host, port)
	lr.err = lr.conn.Connect()
}

// bind this ldapAuthenticationRequest to the ldap server using bindDN and bindpw
func (lr *ldapAuthenticationRequest) bind(bindDN, bindPassword string) {
	if lr.err != nil {
		return
	}
	lr.err = lr.conn.Bind(bindDN, bindPassword)
}

// authenticateUser finds the user given in username and attempts to bind
// (check the password) of the given user.  Returns nil on success and
// an error on absence of success.
func (lr *ldapAuthenticationRequest) authenticateUser(username, password, baseDN, filterTemplate string) error {
	if lr.err != nil {
		return lr.err
	}

	search_request := ldap.NewSimpleSearchRequest(baseDN, ldap.ScopeWholeSubtree,
		fmt.Sprintf(filterTemplate, username), []string{"cn"})
	if result, err := lr.conn.Search(search_request); err != nil {
		lr.err = err
	} else {
		if len(result.Entries) != 1 {
			lr.err = errors.New(fmt.Sprintf("Unexpected number of entries %d matched username\n", len(result.Entries)))
			return lr.err
		}
		dn := result.Entries[0].DN
		lr.err = lr.conn.Bind(dn, password)
	}
	return lr.err
}

func (lr *ldapAuthenticationRequest) close() {
	lr.conn.Close()
}

func (la ldapAuthenticator) Authenticate(username, password string) (User, error) {
	request := ldapAuthenticationRequest{}
	defer request.close()
	request.connect(la.host, la.port)
	request.bind(la.bindDN, la.bindpw)
	if err := request.authenticateUser(username, password, la.baseDN, la.filterTemplate); err != nil {
		return nil, err
	}
	return fakeUser{username}, nil
}
