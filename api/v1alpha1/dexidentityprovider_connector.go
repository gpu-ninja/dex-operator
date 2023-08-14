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

package v1alpha1

import "github.com/gpu-ninja/operator-utils/reference"

// DexIdentityProviderConnectorType defines the connector type to use.
// We only support a subset of the available Dex connectors atm.
type DexIdentityProviderConnectorType string

const (
	DexIdentityProviderConnectorTypeLDAP DexIdentityProviderConnectorType = "ldap"
	DexIdentityProviderConnectorTypeOIDC DexIdentityProviderConnectorType = "oidc"
)

// DexIdentityProviderConnectorLDAPUserSearchSpec holds configuration for searching LDAP users.
type DexIdentityProviderConnectorLDAPUserSearchSpec struct {
	// BaseDN to start the search from. For example "cn=users,dc=example,dc=com"
	BaseDN string `json:"baseDN"`
	// Filter is an optional filter to apply when searching the directory. For example "(objectClass=person)"
	Filter string `json:"filter,omitempty"`
	// Username is the attribute to match against the inputted username. This will be translated and combined
	// with the other filter as "(<attr>=<username>)".
	Username string `json:"username"`
	// Scope is the optional scope of the search (default "sub").
	// Can either be:
	// * "sub" - search the whole sub tree
	// * "one" - only search one level
	// +kubebuilder:validation:Enum=sub;one
	Scope string `json:"scope,omitempty"`
	// IDAttr is the attribute to use as the user ID (default "uid").
	IDAttr string `json:"idAttr,omitempty"`
	// EmailAttr is the attribute to use as the user email (default "mail").
	EmailAttr string `json:"emailAttr,omitempty"`
	// NameAttr is the attribute to use as the display name for the user.
	NameAttr string `json:"nameAttr,omitempty"`
	// PreferredUsernameAttr is the attribute to use as the preferred username for the user.
	PreferredUsernameAttr string `json:"preferredUsernameAttr,omitempty"`
	// EmailSuffix if set, will be appended to the idAttr to construct the email claim.
	// This should not include the @ character.
	EmailSuffix string `json:"emailSuffix,omitempty"`
}

// DexIdentityProviderConnectorLDAPGroupSearchUserMatcher holds information about user and group matching.
type DexIdentityProviderConnectorLDAPGroupSearchUserMatcher struct {
	// UserAttr is the attribute to match against the user ID.
	UserAttr string `json:"userAttr"`
	// GroupAttr is the attribute to match against the group ID.
	GroupAttr string `json:"groupAttr"`
}

// DexIdentityProviderConnectorLDAPGroupSearchSpec holds configuration for searching LDAP groups.
type DexIdentityProviderConnectorLDAPGroupSearchSpec struct {
	// BaseDN to start the search from. For example "cn=groups,dc=example,dc=com"
	BaseDN string `json:"baseDN"`
	// Filter is an optional filter to apply when searching the directory. For example "(objectClass=posixGroup)"
	Filter string `json:"filter,omitempty"`
	// Scope is the optional scope of the search (default "sub").
	// Can either be:
	// * "sub" - search the whole sub tree
	// * "one" - only search one level
	// +kubebuilder:validation:Enum=sub;one
	Scope string `json:"scope,omitempty"`
	// NameAttr is the attribute of the group that represents its name.
	NameAttr string `json:"nameAttr"`
	// UserMatchers is an array of the field pairs used to match a user to a group.
	// See the "DexIdentityProviderConnectorLDAPGroupSearchUserMatcher" struct for the
	// exact field names
	//
	// Each pair adds an additional requirement to the filter that an attribute in the group
	// match the user's attribute value. For example that the "members" attribute of
	// a group matches the "uid" of the user. The exact filter being added is:
	//
	//   (userMatchers[n].<groupAttr>=userMatchers[n].<userAttr value>)
	//
	UserMatchers []DexIdentityProviderConnectorLDAPGroupSearchUserMatcher `json:"userMatchers"`
}

// DexIdentityProviderConnectorLDAPSpec holds configuration for the LDAP connector.
type DexIdentityProviderConnectorLDAPSpec struct {
	// Host is the host and optional port of the LDAP server.
	// If port isn't supplied, it will be guessed based on the TLS configuration.
	Host string `json:"host"`
	// InsecureNoSSL is required to connect to a server without TLS.
	InsecureNoSSL bool `json:"insecureNoSSL,omitempty"`
	// InsecureSkipVerify allows connecting to a server without
	// verifying the TLS certificate.
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`
	// StartTLS allows connecting to a server that supports the StartTLS command.
	// If unsupplied secure connections will use the LDAPS protocol.
	StartTLS bool `json:"startTLS,omitempty"`
	// CASecretRef is an optional reference to a secret containing the CA certificate.
	CASecretRef *reference.LocalSecretReference `json:"caSecretRef,omitempty"`
	// ClientCertificateSecretRef is an optional reference to a secret containing the client certificate and key.
	ClientCertificateSecretRef *reference.LocalSecretReference `json:"clientCertificateSecretRef,omitempty"`
	// BindUsername is the DN of the user to bind with.
	// The connector uses these credentials to search for users and groups.
	BindUsername string `json:"bindUsername"`
	// BindPasswordSecretRef is a reference to a secret containing the bind password.
	// The connector uses these credentials to search for users and groups.
	BindPasswordSecretRef reference.LocalSecretReference `json:"bindPasswordSecretRef"`
	// UsernamePrompt allows users to override the username attribute (displayed
	// in the username/password prompt). If unset, the handler will use
	// "Username".
	UsernamePrompt string `json:"usernamePrompt,omitempty"`
	// UserSearch contains configuration for searching LDAP users.
	UserSearch DexIdentityProviderConnectorLDAPUserSearchSpec `json:"userSearch"`
	// GroupSearch contains configuration for searching LDAP groups.
	GroupSearch DexIdentityProviderConnectorLDAPGroupSearchSpec `json:"groupSearch"`
}

// DexIdentityProviderConnectorOIDCClaimMapping holds configuration for OIDC claim mapping.
type DexIdentityProviderConnectorOIDCClaimMapping struct {
	// PreferredUsernameKey is the key which contains the preferred username claims, defaults to "preferred_username".
	PreferredUsernameKey string `json:"preferred_username,omitempty"`
	// EmailKey is the key which contains the email claims, defaults to "email".
	EmailKey string `json:"email,omitempty"`
	// GroupsKey is the key which contains the groups claims, defaults to "groups".
	GroupsKey string `json:"groups,omitempty"`
}

// DexIdentityProviderConnectorOIDCSpec holds configuration for the OIDC connector.
type DexIdentityProviderConnectorOIDCSpec struct {
	// Issuer is the URL of the OIDC issuer.
	Issuer string `json:"issuer"`
	// ClientSecretRef is a reference to a secret containing the OAuth client id and secret.
	ClientSecretRef reference.LocalSecretReference `json:"clientSecretRef"`
	// RedirectURI is the OAuth redirect URI.
	RedirectURI string `json:"redirectURI"`
	// BasicAuthUnsupported causes client_secret to be passed as POST parameters instead of basic
	// auth. This is specifically "NOT RECOMMENDED" by the OAuth2 RFC, but some
	// providers require it.
	//
	// https://tools.ietf.org/html/rfc6749#section-2.3.1
	BasicAuthUnsupported *bool `json:"basicAuthUnsupported,omitempty"`
	// Scopes is an optional list of scopes to request.
	// If omitted, defaults to "profile" and "email".
	Scopes []string `json:"scopes,omitempty"`
	// CASecretRef is an optional reference to a secret containing the CA certificate.
	// Only required if your provider uses a self-signed certificate.
	CASecretRef *reference.LocalSecretReference `json:"caSecretRef,omitempty"`
	// InsecureSkipVerify disables TLS certificate verification.
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`
	// InsecureSkipEmailVerified if set will override the value of email_verified to true in the returned claims.
	InsecureSkipEmailVerified bool `json:"insecureSkipEmailVerified,omitempty"`
	// InsecureEnableGroups enables groups claims.
	InsecureEnableGroups bool `json:"insecureEnableGroups,omitempty"`
	// AcrValues (Authentication Context Class Reference Values) that specifies the Authentication Context Class Values
	// within the Authentication Request that the Authorization Server is being requested to use for
	// processing requests from this Client, with the values appearing in order of preference.
	AcrValues []string `json:"acrValues,omitempty"`
	// GetUserInfo uses the userinfo endpoint to get additional claims for
	// the token. This is especially useful where upstreams return "thin"
	// id tokens
	GetUserInfo bool `json:"getUserInfo,omitempty"`
	// UserIDKey is the claim key to use for the user ID (default sub).
	UserIDKey string `json:"userIDKey,omitempty"`
	// UserNameKey is the claim key to use for the username (default name).
	UserNameKey string `json:"userNameKey,omitempty"`
	// PromptType will be used fot the prompt parameter (when offline_access, by default prompt=consent).
	PromptType string `json:"promptType,omitempty"`
	// OverrideClaimMapping will be used to override the options defined in claimMappings.
	// i.e. if there are 'email' and `preferred_email` claims available, by default Dex will always use the `email` claim independent of the ClaimMapping.EmailKey.
	// This setting allows you to override the default behavior of Dex and enforce the mappings defined in `claimMapping`.
	// Defaults to false.
	OverrideClaimMapping bool `json:"overrideClaimMapping,omitempty"`
	// ClaimMapping is used to map non-standard claims to standard claims.
	// Some providers return non-standard claims (eg. mail).
	// https://openid.net/specs/openid-connect-core-1_0.html#Claims
	ClaimMapping *DexIdentityProviderConnectorOIDCClaimMapping `json:"claimMapping,omitempty"`
}

// DexIdentityProviderConnectorSpec holds configuration for a connector.
type DexIdentityProviderConnectorSpec struct {
	// Type is the connector type to use.
	//+kubebuilder:validation:Enum=ldap;oidc
	Type DexIdentityProviderConnectorType `json:"type"`
	// Name is the connector name.
	Name string `json:"name"`
	// ID is the connector ID.
	ID string `json:"id"`
	// LDAP holds configuration for the LDAP connector.
	LDAP *DexIdentityProviderConnectorLDAPSpec `json:"ldap,omitempty"`
	// OIDC holds configuration for the OIDC connector.
	OIDC *DexIdentityProviderConnectorOIDCSpec `json:"oidc,omitempty"`
}
