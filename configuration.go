// Configuration objects and functions for configuring Authatron
// AuthConfig provides a parent config object housing configuration
// for each supported authentication type.

package authatron

import (
	"errors"
	"fmt"
	"github.com/gorilla/sessions"
	"os"
	"strconv"
)

// Configuration object for configuring an LDAP connection.
type LDAPAuthConfig struct {
	Host                 string `toml:"host"`
	Port                 uint16 `toml:"port"`
	BindDN               string `toml:"bind_dn"`
	BindPassword         string `toml:"bind_password"`
	BaseDN               string `toml:"base_dn"`
	UserNameLookupFilter string `toml:"username_lookup"`
}

func (lac *LDAPAuthConfig) loadEnv(prefix string) {
	loadStringEnvIntoField(prefix, &lac.Host, "LDAP_HOST")
	loadIntEnvIntoField(prefix, &lac.Port, "LDAP_PORT")
	loadStringEnvIntoField(prefix, &lac.BindDN, "LDAP_BIND_DN")
	loadStringEnvIntoField(prefix, &lac.BindPassword, "LDAP_BIND_PASSWORD")
	loadStringEnvIntoField(prefix, &lac.BaseDN, "LDAP_BASE_DN")
	loadStringEnvIntoField(prefix, &lac.UserNameLookupFilter,
		"LDAP_USERNAME_LOOKUP")
}

type DummyAuthConfig struct {
	DummyPassword string `toml:"dummy-password"`
}

func (ac *DummyAuthConfig) loadEnv(prefix string) {
	loadStringEnvIntoField(prefix, &ac.DummyPassword, "AUTH_DUMMY_PASSWORD")
}

type UserStoreConfig struct {
	CookieSecret string `toml:"cookie-secret"`
}

func (usc *UserStoreConfig) loadEnv(prefix string) {
	loadStringEnvIntoField(prefix, &usc.CookieSecret, "AUTH_COOKIE_SECRET")
}

// Configuration object for configuring Authatron.
type AuthConfig struct {
	// Select the authentication engine
	Type string `toml:"type"`
	DummyAuthConfig
	LDAPAuthConfig
	UserStoreConfig
}

func (ac *AuthConfig) loadEnv(prefix string) {
	ac.DummyAuthConfig.loadEnv(prefix)
	ac.LDAPAuthConfig.loadEnv(prefix)
	ac.UserStoreConfig.loadEnv(prefix)
	loadStringEnvIntoField(prefix, &ac.Type, "AUTH_TYPE")
}

// NewAuthenticateServiceFromConfig creates a new AuthenticateService using
// the provided config struct
func NewAuthenticateServiceFromConfig(config *AuthConfig) (AuthenticateService, error) {
	userStore := &cookieUserStore{
		sessions.NewCookieStore([]byte("secret")),
		config.CookieSecret,
	}
	var authenticator Authenticator
	switch config.Type {
	case "dummy":
		authenticator = fakeAuthenticator{config.DummyPassword}
	case "ldap":
		authenticator = NewLDAPAuthenticatorFromConfig(config.LDAPAuthConfig)
	default:
		message := fmt.Sprintf("Unknown authenticate service type: %s", config.Type)
		return nil, errors.New(message)
	}
	return &struct {
		UserStore
		Authenticator
	}{
		userStore,
		authenticator,
	}, nil
}

func loadStringEnvIntoField(prefix string, field *string, envVar string) {
	if value := os.Getenv(envVar); value != "" {
		*field = value
	}
}

func loadIntEnvIntoField(prefix string, field *uint16, envVar string) {
	if value := os.Getenv(envVar); value != "" {
		intValue, _ := strconv.ParseUint(value, 10, 16)
		*field = uint16(intValue)
	}
}

// UpdateConfigFromEnvironmentVariables returns an updated config updated
// loading in any environment variables.  Environment variables can be prefixed
// using prefix allowing individual applications to namespace env vars
func UpdateConfigFromEnvironmentVariables(prefix string, config *AuthConfig) *AuthConfig {
	config.loadEnv(prefix)
	return config
}
