/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright 2023 Damian Peckett <damian@pecke.tt>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package dex

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// Config is the config format for the main application.
type Config struct {
	Issuer           string      `yaml:"issuer"`
	Storage          Storage     `yaml:"storage"`
	Web              Web         `yaml:"web"`
	GRPC             GRPC        `yaml:"grpc"`
	OAuth2           *OAuth2     `yaml:"oauth2,omitempty"`
	Expiry           *Expiry     `yaml:"expiry,omitempty"`
	Logger           *Logger     `yaml:"logger,omitempty"`
	Frontend         *Frontend   `yaml:"frontend,omitempty"`
	Telemetry        *Telemetry  `yaml:"telemetry,omitempty"`
	Connectors       []Connector `yaml:"connectors"`
	EnablePasswordDB bool        `yaml:"enablePasswordDB"`
}

// OAuth2 describes enabled OAuth2 extensions.
type OAuth2 struct {
	// list of allowed grant types,
	// defaults to all supported types
	GrantTypes    []string `yaml:"grantTypes,omitempty"`
	ResponseTypes []string `yaml:"responseTypes,omitempty"`
	// If specified, do not prompt the user to approve client authorization. The
	// act of logging in implies authorization.
	SkipApprovalScreen bool `yaml:"skipApprovalScreen,omitempty"`
	// If specified, show the connector selection screen even if there's only one
	AlwaysShowLoginScreen bool `yaml:"alwaysShowLoginScreen,omitempty"`
	// This is the connector that can be used for password grant
	PasswordConnector string `yaml:"passwordConnector,omitempty"`
}

// Web is the config format for the HTTP server.
type Web struct {
	HTTP           string   `yaml:"http,omitempty"`
	HTTPS          string   `yaml:"https,omitempty"`
	TLSCert        string   `yaml:"tlsCert,omitempty"`
	TLSKey         string   `yaml:"tlsKey,omitempty"`
	AllowedOrigins []string `yaml:"allowedOrigins,omitempty"`
}

// GRPC is the config for the gRPC API.
type GRPC struct {
	// The port to listen on.
	Addr        string `yaml:"addr,omitempty"`
	TLSCert     string `yaml:"tlsCert,omitempty"`
	TLSKey      string `yaml:"tlsKey,omitempty"`
	TLSClientCA string `yaml:"tlsClientCA,omitempty"`
	Reflection  bool   `yaml:"reflection,omitempty"`
}

// Storage holds app's storage configuration.
type Storage struct {
	Type   string        `yaml:"type"`
	Config StorageConfig `yaml:"config"`
}

// StorageConfig is a configuration that can create a storage.
type StorageConfig struct {
	SQLite3  *SQLite3Config  `yaml:"-"`
	Postgres *PostgresConfig `yaml:"-"`
}

func (c StorageConfig) MarshalYAML() (any, error) {
	var node yaml.Node
	if c.SQLite3 != nil {
		if err := node.Encode(c.SQLite3); err != nil {
			return nil, err
		}

		return &node, nil
	} else if c.Postgres != nil {
		if err := node.Encode(c.Postgres); err != nil {
			return nil, err
		}

		return &node, nil
	}

	return nil, fmt.Errorf("invalid storage configuration")
}

// Connector is a magical type that can unmarshal YAML dynamically. The
// Type field determines the connector type, which is then customized for Config.
type Connector struct {
	Type   string          `yaml:"type"`
	Name   string          `yaml:"name"`
	ID     string          `yaml:"id"`
	Config ConnectorConfig `yaml:"config"`
}

// ConnectorConfig is a configuration that can create a connector.
type ConnectorConfig struct {
	LDAP *LDAPConnectorConfig `yaml:"-"`
	OIDC *OIDCConnectorConfig `yaml:"-"`
}

func (c ConnectorConfig) MarshalYAML() (any, error) {
	var node yaml.Node
	if c.LDAP != nil {
		if err := node.Encode(c.LDAP); err != nil {
			return nil, err
		}

		return &node, nil
	} else if c.OIDC != nil {
		if err := node.Encode(c.OIDC); err != nil {
			return nil, err
		}

		return &node, nil
	}

	return nil, fmt.Errorf("invalid connector configuration")
}

// Expiry holds configuration for the validity period of components.
type Expiry struct {
	// SigningKeys defines the duration of time after which the SigningKeys will be rotated.
	SigningKeys string `yaml:"signingKeys,omitempty"`
	// IdTokens defines the duration of time for which the IdTokens will be valid.
	IDTokens string `yaml:"idTokens,omitempty"`
	// AuthRequests defines the duration of time for which the AuthRequests will be valid.
	AuthRequests string `yaml:"authRequests,omitempty"`
	// DeviceRequests defines the duration of time for which the DeviceRequests will be valid.
	DeviceRequests string `yaml:"deviceRequests,omitempty"`
	// RefreshTokens defines refresh tokens expiry policy
	RefreshTokens *RefreshToken `yaml:"refreshTokens,omitempty"`
}

// Logger holds configuration required to customize logging for dex.
type Logger struct {
	// Level sets logging level severity.
	Level string `yaml:"level,omitempty"`
	// Format specifies the format to be used for logging.
	Format string `yaml:"format,omitempty"`
}

// Telemetry is the config format for telemetry including the HTTP server config.
type Telemetry struct {
	HTTP string `json:"http"`
}

type RefreshToken struct {
	DisableRotation   bool   `yaml:"disableRotation,omitempty"`
	ReuseInterval     string `yaml:"reuseInterval,omitempty"`
	AbsoluteLifetime  string `yaml:"absoluteLifetime,omitempty"`
	ValidIfNotUsedFor string `yaml:"validIfNotUsedFor,omitempty"`
}

// Frontend holds the server's frontend templates and asset configuration.
type Frontend struct {
	// A file path to static web assets.
	//
	// It is expected to contain the following directories:
	//
	//   * static - Static static served at "( issuer URL )/static".
	//   * templates - HTML templates controlled by dex.
	//   * themes/(theme) - Static static served at "( issuer URL )/theme".
	Dir string `yaml:"dir,omitempty"`
	// Defaults to "( issuer URL )/theme/logo.png"
	LogoURL string `yaml:"logoURL,omitempty"`
	// Defaults to "dex"
	Issuer string `yaml:"issuer,omitempty"`
	// Defaults to "light"
	Theme string `yaml:"theme,omitempty"`
	// Map of extra values passed into the templates
	Extra map[string]string `yaml:"extra,omitempty"`
}

type SQLite3Config struct {
	// File to use for SQLite3 storage.
	File string `yaml:"file"`
}

type PostgresConfig struct {
	Database          string            `yaml:"database"`
	User              string            `yaml:"user"`
	Password          string            `yaml:"password"`
	Host              string            `yaml:"host"`
	Port              int               `yaml:"port"`
	ConnectionTimeout *int              `yaml:"connectionTimeout,omitempty"`
	MaxOpenConns      *int              `yaml:"maxOpenConns,omitempty"`
	MaxIdleConns      *int              `yaml:"maxIdleConns,omitempty"`
	ConnMaxLifetime   *int              `yaml:"connMaxLifetime,omitempty"`
	SSL               *SSLStorageConfig `yaml:"ssl,omitempty"`
}

// SSLStorageConfig represents SSL options for network databases.
type SSLStorageConfig struct {
	Mode   string `yaml:"mode,omitempty"`
	CAFile string `yaml:"caFile,omitempty"`
	// Files for client auth.
	KeyFile  string `yaml:"keyFile,omitempty"`
	CertFile string `yaml:"certFile,omitempty"`
}

// LDAPConnectorConfig holds configuration options for LDAP logins.
type LDAPConnectorConfig struct {
	// The host and optional port of the LDAP server. If port isn't supplied, it will be
	// guessed based on the TLS configuration. 389 or 636.
	Host string `yaml:"host"`
	// Required if LDAP host does not use TLS.
	InsecureNoSSL bool `yaml:"insecureNoSSL,omitempty"`
	// Don't verify the CA.
	InsecureSkipVerify bool `yaml:"insecureSkipVerify,omitempty"`
	// Connect to the insecure port then issue a StartTLS command to negotiate a
	// secure connection. If unsupplied secure connections will use the LDAPS
	// protocol.
	StartTLS bool `yaml:"startTLS,omitempty"`
	// Path to a trusted root certificate file.
	RootCA string `yaml:"rootCA,omitempty"`
	// Path to a client cert file generated by rootCA.
	ClientCert string `yaml:"clientCert,omitempty"`
	// Path to a client private key file generated by rootCA.
	ClientKey string `yaml:"clientKey,omitempty"`
	// BindDN and BindPW for an application service account. The connector uses these
	// credentials to search for users and groups.
	BindDN string `yaml:"bindDN"`
	BindPW string `yaml:"bindPW"`
	// UsernamePrompt allows users to override the username attribute (displayed
	// in the username/password prompt). If unset, the handler will use
	// "Username".
	UsernamePrompt string `yaml:"usernamePrompt,omitempty"`
	// User entry search configuration.
	UserSearch LDAPConnectorUserSearch `yaml:"userSearch"`
	// Group search configuration.
	GroupSearch LDAPConnectorGroupSearch `yaml:"groupSearch"`
}

type LDAPConnectorUserSearch struct {
	// BaseDN to start the search from. For example "cn=users,dc=example,dc=com"
	BaseDN string `yaml:"baseDN"`
	// Optional filter to apply when searching the directory. For example "(objectClass=person)"
	Filter string `yaml:"filter,omitempty"`
	// Attribute to match against the inputted username. This will be translated and combined
	// with the other filter as "(<attr>=<username>)".
	Username string `yaml:"username"`
	// Can either be:
	// * "sub" - search the whole sub tree
	// * "one" - only search one level
	Scope string `yaml:"scope,omitempty"`
	// A mapping of attributes on the user entry to claims.
	IDAttr                    string `yaml:"idAttr,omitempty"`                // Defaults to "uid"
	EmailAttr                 string `yaml:"emailAttr,omitempty"`             // Defaults to "mail"
	NameAttr                  string `yaml:"nameAttr,omitempty"`              // No default.
	PreferredUsernameAttrAttr string `yaml:"preferredUsernameAttr,omitempty"` // No default.
	// If this is set, the email claim of the id token will be constructed from the idAttr and
	// value of emailSuffix. This should not include the @ character.
	EmailSuffix string `yaml:"emailSuffix,omitempty"` // No default.
}

type LDAPConnectorGroupSearch struct {
	// BaseDN to start the search from. For example "cn=groups,dc=example,dc=com"
	BaseDN string `yaml:"baseDN"`
	// Optional filter to apply when searching the directory. For example "(objectClass=posixGroup)"
	Filter string `yaml:"filter,omitempty"`
	Scope  string `yaml:"scope,omitempty"` // Defaults to "sub"
	// The attribute of the group that represents its name.
	NameAttr string `yaml:"nameAttr"`
	// Array of the field pairs used to match a user to a group.
	// See the "UserMatcher" struct for the exact field names
	//
	// Each pair adds an additional requirement to the filter that an attribute in the group
	// match the user's attribute value. For example that the "members" attribute of
	// a group matches the "uid" of the user. The exact filter being added is:
	//
	//   (userMatchers[n].<groupAttr>=userMatchers[n].<userAttr value>)
	//
	UserMatchers []LDAPConnectorUserMatcher `yaml:"userMatchers"`
}

// LDAPConnectorUserMatcher holds information about user and group matching.
type LDAPConnectorUserMatcher struct {
	UserAttr  string `yaml:"userAttr"`
	GroupAttr string `yaml:"groupAttr"`
}

// OIDCConnectorConfig holds configuration options for OpenID Connect logins.
type OIDCConnectorConfig struct {
	Issuer       string `yaml:"issuer"`
	ClientID     string `yaml:"clientID"`
	ClientSecret string `yaml:"clientSecret"`
	RedirectURI  string `yaml:"redirectURI"`
	// Causes client_secret to be passed as POST parameters instead of basic
	// auth. This is specifically "NOT RECOMMENDED" by the OAuth2 RFC, but some
	// providers require it.
	//
	// https://tools.ietf.org/html/rfc6749#section-2.3.1
	BasicAuthUnsupported *bool    `yaml:"basicAuthUnsupported,omitempty"`
	Scopes               []string `yaml:"scopes,omitempty"` // defaults to "profile" and "email"
	// Certificates for SSL validation
	RootCAs []string `yaml:"rootCAs,omitempty"`
	// Override the value of email_verified to true in the returned claims
	InsecureSkipEmailVerified bool `yaml:"insecureSkipEmailVerified,omitempty"`
	// InsecureEnableGroups enables groups claims. This is disabled by default until https://github.com/dexidp/dex/issues/1065 is resolved
	InsecureEnableGroups bool `yaml:"insecureEnableGroups,omitempty"`
	// AcrValues (Authentication Context Class Reference Values) that specifies the Authentication Context Class Values
	// within the Authentication Request that the Authorization Server is being requested to use for
	// processing requests from this Client, with the values appearing in order of preference.
	AcrValues []string `yaml:"acrValues,omitempty"`
	// Disable certificate verification
	InsecureSkipVerify bool `yaml:"insecureSkipVerify,omitempty"`
	// GetUserInfo uses the userinfo endpoint to get additional claims for
	// the token. This is especially useful where upstreams return "thin"
	// id tokens
	GetUserInfo bool   `yaml:"getUserInfo,omitempty"`
	UserIDKey   string `yaml:"userIDKey,omitempty"`
	UserNameKey string `yaml:"userNameKey,omitempty"`
	// PromptType will be used fot the prompt parameter (when offline_access, by default prompt=consent)
	PromptType string `yaml:"promptType,omitempty"`
	// OverrideClaimMapping will be used to override the options defined in claimMappings.
	// i.e. if there are 'email' and `preferred_email` claims available, by default Dex will always use the `email` claim independent of the ClaimMapping.EmailKey.
	// This setting allows you to override the default behavior of Dex and enforce the mappings defined in `claimMapping`.
	OverrideClaimMapping bool                      `yaml:"overrideClaimMapping,omitempty"` // defaults to false
	ClaimMapping         OIDCConnectorClaimMapping `yaml:"claimMapping"`
}

type OIDCConnectorClaimMapping struct {
	// Configurable key which contains the preferred username claims
	PreferredUsernameKey string `yaml:"preferred_username,omitempty"` // defaults to "preferred_username"
	// Configurable key which contains the email claims
	EmailKey string `yaml:"email,omitempty"` // defaults to "email"
	// Configurable key which contains the groups claims
	GroupsKey string `yaml:"groups,omitempty"` // defaults to "groups"
}
