//The MIT License (MIT)
//
//Copyright (c) 2015 samuelrayment
//
//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files (the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions:
//
//The above copyright notice and this permission notice shall be included in all
//copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//SOFTWARE.

/*
Package Authatron provides authentication interfaces for authenticating users
in go.  Currently fake (fixed password) and LDAP authentication is supported.

Configuration

Authatron supports configuration by creating an AuthConfig programmatically,
a default empty config can be created using NewLDAPAuthenticatorFromConfig.
AuthConfig is marked up using struct tags to be loaded from a toml file using:
https://github.com/BurntSushi/toml

Configuration can also be loaded from environment variables using
UpdateConfigFromEnvironmentVariables which can take a prefix to configure a
prefix for the environment variables.

Interface

Once configured NewAuthenticateServiceFromConfig can be used to create a new
AuthenticateService.  The AuthenticateService consists of two smaller interfaces
the UserStore and Authenticator.  The UserStore is responsible for storing and
retrieving user credentials and the Authenticator is responsible for initially
authenticating a user.

UserStore - Currently the only implementation of UserStore is a cookie user store
using http://github.com/gorilla/securecookie.

Authenticator - There are currently two Authenticator implementations

	- 'dummy' which allows a password to be set and will authenticate all users using that password.
	- 'ldap' which authenticates users against and LDAP server.

Integrating

Soon...

*/
package authatron
