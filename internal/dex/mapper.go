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
	"context"
	"fmt"
	"path/filepath"

	dexv1alpha1 "github.com/gpu-ninja/dex-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	CertsBase = "/etc/dex/ssl"
)

func ConfigFromCR(ctx context.Context, reader client.Reader, scheme *runtime.Scheme, idp *dexv1alpha1.DexIdentityProvider) (*Config, error) {
	var webTLSCertFile, webTLSKeyFile string
	if idp.Spec.Web.CertificateSecretRef != nil {
		webTLSCertFile = filepath.Join(CertsBase, idp.Spec.Web.CertificateSecretRef.Name, "tls.crt")
		webTLSKeyFile = filepath.Join(CertsBase, idp.Spec.Web.CertificateSecretRef.Name, "tls.key")
	}

	var grpcTLSCertFile, grpcTLSKeyFile string
	if idp.Spec.GRPC.CertificateSecretRef != nil {
		grpcTLSCertFile = filepath.Join(CertsBase, idp.Spec.GRPC.CertificateSecretRef.Name, "tls.crt")
		grpcTLSKeyFile = filepath.Join(CertsBase, idp.Spec.GRPC.CertificateSecretRef.Name, "tls.key")
	}

	var grpcClientCAFile string
	if idp.Spec.GRPC.ClientCASecretRef != nil {
		grpcClientCAFile = filepath.Join(CertsBase, idp.Spec.GRPC.ClientCASecretRef.Name, "ca.crt")
	}

	c := &Config{
		Issuer: idp.Spec.Issuer,
		Web: Web{
			HTTP:           idp.Spec.Web.HTTP,
			HTTPS:          idp.Spec.Web.HTTPS,
			TLSCert:        webTLSCertFile,
			TLSKey:         webTLSKeyFile,
			AllowedOrigins: idp.Spec.Web.AllowedOrigins,
		},
		GRPC: GRPC{
			Addr:        idp.Spec.GRPC.Addr,
			TLSCert:     grpcTLSCertFile,
			TLSKey:      grpcTLSKeyFile,
			TLSClientCA: grpcClientCAFile,
			Reflection:  idp.Spec.GRPC.Reflection,
		},
	}

	if idp.Spec.OAuth2 != nil {
		c.OAuth2 = &OAuth2{
			GrantTypes:            idp.Spec.OAuth2.GrantTypes,
			ResponseTypes:         idp.Spec.OAuth2.ResponseTypes,
			SkipApprovalScreen:    idp.Spec.OAuth2.SkipApprovalScreen,
			AlwaysShowLoginScreen: idp.Spec.OAuth2.AlwaysShowLoginScreen,
			PasswordConnector:     idp.Spec.OAuth2.PasswordConnector,
		}
	}

	if idp.Spec.Expiry != nil {
		c.Expiry = &Expiry{
			SigningKeys:    humanReadableDuration(idp.Spec.Expiry.SigningKeys),
			IDTokens:       humanReadableDuration(idp.Spec.Expiry.IDTokens),
			AuthRequests:   humanReadableDuration(idp.Spec.Expiry.AuthRequests),
			DeviceRequests: humanReadableDuration(idp.Spec.Expiry.DeviceRequests),
			RefreshTokens: &RefreshToken{
				DisableRotation:   idp.Spec.Expiry.RefreshTokens.DisableRotation,
				ReuseInterval:     humanReadableDuration(idp.Spec.Expiry.RefreshTokens.ReuseInterval),
				AbsoluteLifetime:  humanReadableDuration(idp.Spec.Expiry.RefreshTokens.AbsoluteLifetime),
				ValidIfNotUsedFor: humanReadableDuration(idp.Spec.Expiry.RefreshTokens.ValidIfNotUsedFor),
			},
		}
	}

	if idp.Spec.Logger != nil {
		c.Logger = &Logger{
			Level:  idp.Spec.Logger.Level,
			Format: idp.Spec.Logger.Format,
		}
	}

	if idp.Spec.Frontend != nil {
		c.Frontend = &Frontend{
			Dir:     idp.Spec.Frontend.Dir,
			LogoURL: idp.Spec.Frontend.LogoURL,
			Issuer:  idp.Spec.Frontend.Issuer,
			Theme:   idp.Spec.Frontend.Theme,
		}
	}

	if idp.Spec.Storage.Type == dexv1alpha1.DexIdentityProviderStorageTypeMemory {
		c.Storage.Type = string(idp.Spec.Storage.Type)
	} else if idp.Spec.Storage.Type == dexv1alpha1.DexIdentityProviderStorageTypeSqlite3 &&
		idp.Spec.Storage.Sqlite3 != nil {
		c.Storage = sqlite3StorageFromCR(idp.Spec.Storage)
	} else if idp.Spec.Storage.Type == dexv1alpha1.DexIdentityProviderStorageTypePostgres &&
		idp.Spec.Storage.Postgres != nil {
		postgresStorage, err := postgresStorageFromCR(ctx, reader, scheme, idp, idp.Spec.Storage)
		if err != nil {
			return nil, err
		}

		c.Storage = *postgresStorage
	} else {
		return nil, fmt.Errorf("invalid storage configuration")
	}

	for _, connector := range idp.Spec.Connectors {
		if connector.Type == dexv1alpha1.DexIdentityProviderConnectorTypeLDAP &&
			connector.LDAP != nil {
			ldapConnector, err := ldapConnectorFromCR(ctx, reader, scheme, idp, connector)
			if err != nil {
				return nil, err
			}

			c.Connectors = append(c.Connectors, *ldapConnector)
		} else if connector.Type == dexv1alpha1.DexIdentityProviderConnectorTypeOIDC &&
			connector.OIDC != nil {
			oidcConnector, err := oidcConnectorFromCR(ctx, reader, scheme, idp, connector)
			if err != nil {
				return nil, err
			}

			c.Connectors = append(c.Connectors, *oidcConnector)
		} else {
			return nil, fmt.Errorf("invalid connector configuration")
		}
	}

	return c, nil
}

func sqlite3StorageFromCR(storage dexv1alpha1.DexIdentityProviderStorageSpec) Storage {
	return Storage{
		Type: string(storage.Type),
		Config: StorageConfig{
			SQLite3: &SQLite3Config{
				File: storage.Sqlite3.File,
			},
		},
	}
}

func postgresStorageFromCR(ctx context.Context, reader client.Reader, scheme *runtime.Scheme, idp *dexv1alpha1.DexIdentityProvider, storage dexv1alpha1.DexIdentityProviderStorageSpec) (*Storage, error) {
	credentialsSecret, err := storage.Postgres.CredentialsSecretRef.Resolve(ctx, reader, scheme, idp)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve postgres credentials secret: %w", err)
	}

	var ssl *SSLStorageConfig
	if storage.Postgres.SSL != nil {
		var caFile string
		if storage.Postgres.SSL.CASecretRef != nil {
			caFile = filepath.Join(CertsBase, storage.Postgres.SSL.CASecretRef.Name, "ca.crt")
		}

		var keyFile, certFile string
		if storage.Postgres.SSL.ClientCertificateSecretRef != nil {
			keyFile = filepath.Join(CertsBase, storage.Postgres.SSL.ClientCertificateSecretRef.Name, "tls.key")
			certFile = filepath.Join(CertsBase, storage.Postgres.SSL.ClientCertificateSecretRef.Name, "tls.crt")
		}

		ssl = &SSLStorageConfig{
			Mode:     storage.Postgres.SSL.Mode,
			CAFile:   caFile,
			KeyFile:  keyFile,
			CertFile: certFile,
		}
	}

	return &Storage{
		Type: string(storage.Type),
		Config: StorageConfig{
			Postgres: &PostgresConfig{
				Database:          storage.Postgres.Database,
				User:              string(credentialsSecret.(*corev1.Secret).Data["username"]),
				Password:          string(credentialsSecret.(*corev1.Secret).Data["password"]),
				Host:              storage.Postgres.Host,
				Port:              storage.Postgres.Port,
				ConnectionTimeout: ptr.To(int(storage.Postgres.ConnectionTimeout.Duration.Seconds())),
				MaxOpenConns:      storage.Postgres.MaxOpenConns,
				MaxIdleConns:      storage.Postgres.MaxIdleConns,
				ConnMaxLifetime:   ptr.To(int(storage.Postgres.ConnMaxLifetime.Duration.Seconds())),
				SSL:               ssl,
			},
		},
	}, nil
}

func ldapConnectorFromCR(ctx context.Context, reader client.Reader, scheme *runtime.Scheme, idp *dexv1alpha1.DexIdentityProvider, connector dexv1alpha1.DexIdentityProviderConnectorSpec) (*Connector, error) {
	bindCredentialsSecret, err := connector.LDAP.BindCredentialsSecretRef.Resolve(ctx, reader, scheme, idp)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve bind credentials secret: %w", err)
	}

	var caFile string
	if connector.LDAP.CASecretRef != nil {
		caFile = filepath.Join(CertsBase, connector.LDAP.CASecretRef.Name, "ca.crt")
	}

	var clientCertFile, clientKeyFile string
	if connector.LDAP.ClientCertificateSecretRef != nil {
		clientCertFile = filepath.Join(CertsBase, connector.LDAP.ClientCertificateSecretRef.Name, "tls.crt")
		clientKeyFile = filepath.Join(CertsBase, connector.LDAP.ClientCertificateSecretRef.Name, "tls.key")
	}

	userMatchers := make([]LDAPConnectorUserMatcher, len(connector.LDAP.GroupSearch.UserMatchers))
	for i, matcher := range connector.LDAP.GroupSearch.UserMatchers {
		userMatchers[i] = LDAPConnectorUserMatcher{
			UserAttr:  matcher.UserAttr,
			GroupAttr: matcher.GroupAttr,
		}
	}

	return &Connector{
		Type: string(connector.Type),
		ID:   string(connector.ID),
		Name: string(connector.Name),
		Config: ConnectorConfig{
			LDAP: &LDAPConnectorConfig{

				Host:               connector.LDAP.Host,
				InsecureNoSSL:      connector.LDAP.InsecureNoSSL,
				InsecureSkipVerify: connector.LDAP.InsecureSkipVerify,
				StartTLS:           connector.LDAP.StartTLS,
				RootCA:             caFile,
				ClientCert:         clientCertFile,
				ClientKey:          clientKeyFile,
				BindDN:             string(bindCredentialsSecret.(*corev1.Secret).Data["username"]),
				BindPW:             string(bindCredentialsSecret.(*corev1.Secret).Data["password"]),
				UsernamePrompt:     connector.LDAP.UsernamePrompt,
				UserSearch: LDAPConnectorUserSearch{
					BaseDN:                    connector.LDAP.UserSearch.BaseDN,
					Filter:                    connector.LDAP.UserSearch.Filter,
					Username:                  connector.LDAP.UserSearch.Username,
					Scope:                     connector.LDAP.UserSearch.Scope,
					IDAttr:                    connector.LDAP.UserSearch.IDAttr,
					EmailAttr:                 connector.LDAP.UserSearch.EmailAttr,
					NameAttr:                  connector.LDAP.UserSearch.NameAttr,
					PreferredUsernameAttrAttr: connector.LDAP.UserSearch.PreferredUsernameAttr,
					EmailSuffix:               connector.LDAP.UserSearch.EmailSuffix,
				},
				GroupSearch: LDAPConnectorGroupSearch{
					BaseDN:       connector.LDAP.GroupSearch.BaseDN,
					Filter:       connector.LDAP.GroupSearch.Filter,
					Scope:        connector.LDAP.GroupSearch.Scope,
					UserMatchers: userMatchers,
					NameAttr:     connector.LDAP.GroupSearch.NameAttr,
				},
			},
		},
	}, nil
}

func oidcConnectorFromCR(ctx context.Context, reader client.Reader, scheme *runtime.Scheme, idp *dexv1alpha1.DexIdentityProvider, connector dexv1alpha1.DexIdentityProviderConnectorSpec) (*Connector, error) {
	clientSecret, err := connector.OIDC.ClientSecretRef.Resolve(ctx, reader, scheme, idp)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve client secret: %w", err)
	}

	var caFile string
	if connector.OIDC.CASecretRef != nil {
		caFile = filepath.Join(CertsBase, connector.OIDC.CASecretRef.Name, "ca.crt")
	}

	var claimMapping OIDCConnectorClaimMapping
	if connector.OIDC.ClaimMapping != nil {
		claimMapping = OIDCConnectorClaimMapping{
			PreferredUsernameKey: connector.OIDC.ClaimMapping.PreferredUsernameKey,
			EmailKey:             connector.OIDC.ClaimMapping.EmailKey,
			GroupsKey:            connector.OIDC.ClaimMapping.GroupsKey,
		}
	}

	return &Connector{
		Type: string(connector.Type),
		ID:   string(connector.ID),
		Name: string(connector.Name),
		Config: ConnectorConfig{
			OIDC: &OIDCConnectorConfig{
				Issuer:                    connector.OIDC.Issuer,
				ClientID:                  string(clientSecret.(*corev1.Secret).Data["id"]),
				ClientSecret:              string(clientSecret.(*corev1.Secret).Data["secret"]),
				RedirectURI:               connector.OIDC.RedirectURI,
				BasicAuthUnsupported:      connector.OIDC.BasicAuthUnsupported,
				Scopes:                    connector.OIDC.Scopes,
				RootCAs:                   []string{caFile},
				InsecureSkipEmailVerified: connector.OIDC.InsecureSkipEmailVerified,
				InsecureEnableGroups:      connector.OIDC.InsecureEnableGroups,
				AcrValues:                 connector.OIDC.AcrValues,
				InsecureSkipVerify:        connector.OIDC.InsecureSkipVerify,
				GetUserInfo:               connector.OIDC.GetUserInfo,
				UserIDKey:                 connector.OIDC.UserIDKey,
				UserNameKey:               connector.OIDC.UserNameKey,
				PromptType:                connector.OIDC.PromptType,
				OverrideClaimMapping:      connector.OIDC.OverrideClaimMapping,
				ClaimMapping:              claimMapping,
			},
		},
	}, nil
}

func humanReadableDuration(d *metav1.Duration) string {
	if d == nil {
		return ""
	}

	totalHours := d.Duration.Hours()

	days := int(totalHours) / 24
	hours := int(totalHours) % 24
	minutes := int(d.Duration.Minutes()) % 60
	seconds := int(d.Duration.Seconds()) % 60

	if days > 0 {
		return fmt.Sprintf("%dh", int(totalHours))
	}
	if hours > 0 {
		return fmt.Sprintf("%dh", hours)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm", minutes)
	}

	return fmt.Sprintf("%ds", seconds)
}
