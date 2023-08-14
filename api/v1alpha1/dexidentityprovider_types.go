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

import (
	"context"
	"fmt"

	"github.com/gpu-ninja/dex-operator/api"
	"github.com/gpu-ninja/operator-utils/reference"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// DexIdentityProviderOAuth2Spec holds configuration for OAuth2.
type DexIdentityProviderOAuth2Spec struct {
	// GrantTypes is a list of allowed grant types, defaults to all supported types.
	GrantTypes []string `json:"grantTypes,omitempty"`
	// ResponseTypes is a list of allowed response types, defaults to all supported types.
	ResponseTypes []string `json:"responseTypes,omitempty"`
	// SkipApprovalScreen, if specified, do not prompt the user to approve client authorization. The
	// act of logging in implies authorization.
	SkipApprovalScreen bool `json:"skipApprovalScreen,omitempty"`
	// AlwaysShowLoginScreen, if specified, show the connector selection screen even if there's only one.
	AlwaysShowLoginScreen bool `json:"alwaysShowLoginScreen,omitempty"`
	// PasswordConnector is a specific connector to user for password grants.
	PasswordConnector string `json:"passwordConnector,omitempty"`
}

// RefreshTokenSpec holds configuration for refresh tokens.
type DexIdentityProviderRefreshTokenSpec struct {
	// DisableRotation disables refresh token rotation.
	DisableRotation bool `json:"disableRotation,omitempty"`
	// ReuseInterval defines the duration of time after which a refresh token can be reused.
	ReuseInterval *metav1.Duration `json:"reuseInterval,omitempty"`
	// AbsoluteLifetime defines the duration of time after which a refresh token will expire.
	AbsoluteLifetime *metav1.Duration `json:"absoluteLifetime,omitempty"`
	// ValidIfNotUsedFor defines the duration of time after which a refresh token will expire if not used.
	ValidIfNotUsedFor *metav1.Duration `json:"validIfNotUsedFor,omitempty"`
}

// DexIdentityProviderExpirySpec holds configuration for the validity of tokens, signing keys, etc.
type DexIdentityProviderExpirySpec struct {
	// SigningKeys defines the duration of time after which the SigningKeys will be rotated.
	SigningKeys *metav1.Duration `json:"signingKeys,omitempty"`
	// IDTokens defines the duration of time for which the IdTokens will be valid.
	IDTokens *metav1.Duration `json:"idTokens,omitempty"`
	// AuthRequests defines the duration of time for which the AuthRequests will be valid.
	AuthRequests *metav1.Duration `json:"authRequests,omitempty"`
	// DeviceRequests defines the duration of time for which the DeviceRequests will be valid.
	DeviceRequests *metav1.Duration `json:"deviceRequests,omitempty"`
	// RefreshTokens defines refresh tokens expiry policy.
	RefreshTokens *DexIdentityProviderRefreshTokenSpec `json:"refreshTokens,omitempty"`
}

// DexIdentityProviderWebSpec holds configuration for the web server.
type DexIdentityProviderWebSpec struct {
	// HTTP is the address to bind HTTP server to.
	HTTP string `json:"http,omitempty"`
	// HTTPS is the address to bind HTTPS server to.
	HTTPS string `json:"https,omitempty"`
	// CertificateSecretRef is an optional reference to a secret containing the TLS certificate and key
	// to use for HTTPS.
	CertificateSecretRef *reference.LocalSecretReference `json:"certificateSecretRef,omitempty"`
	// AllowedOrigins is a list of allowed origins for CORS requests.
	AllowedOrigins []string `json:"allowedOrigins,omitempty"`
	// Annotations is an optional map of additional annotations to add to the web server's service.
	Annotations map[string]string `json:"annotations,omitempty"`
}

// DexIdentityProviderFrontendSpec holds the server's frontend templates and asset configuration.
type DexIdentityProviderFrontendSpec struct {
	// Dir is a file path to static web assets.
	//
	// It is expected to contain the following directories:
	//   * static - Static static served at "( issuer URL )/static".
	//   * templates - HTML templates controlled by dex.
	//   * themes/(theme) - Static static served at "( issuer URL )/theme".
	Dir string `json:"dir,omitempty"`
	// LogoURL is the URL of the logo to use in the HTML templates.
	// Defaults to "( issuer URL )/theme/logo.png"
	LogoURL string `json:"logoURL,omitempty"`
	// Issuer is the name of the issuer, used in the HTML templates.
	// Defaults to "dex".
	Issuer string `json:"issuer,omitempty"`
	// Theme is the name of the theme to use.
	// Defaults to "light".
	Theme string `json:"theme,omitempty"`
}

type DexIdentityProviderLoggerSpec struct {
	// Level sets logging level severity.
	Level string `json:"level,omitempty"`
	// Format specifies the format to be used for logging.
	Format string `json:"format,omitempty"`
}

// DexIdentityProviderGRPCSpec holds configuration for the gRPC server.
type DexIdentityProviderGRPCSpec struct {
	// Addr is the address to bind the gRPC server to.
	Addr string `json:"addr"`
	// CertificateSecretRef is an optional reference to a secret containing the TLS certificate and key
	// to use for the gRPC server.
	CertificateSecretRef *reference.LocalSecretReference `json:"certificateSecretRef,omitempty"`
	// ClientCASecretRef is an optional reference to a secret containing the client CA.
	ClientCASecretRef *reference.LocalSecretReference `json:"clientCASecretRef,omitempty"`
	// Reflection enables gRPC server reflection.
	Reflection bool `json:"reflection,omitempty"`
	// Annotations is an optional map of additional annotations to add to the gRPC server's service.
	Annotations map[string]string `json:"annotations,omitempty"`
}

type DexIdentityProviderLocalStorageSpec struct {
	// MountPath is the path at which the local storage will be mounted in the container.
	MountPath string `json:"mountPath"`
	// Size is the size of the persistent volume that will be
	// used to store Dex's local sqlite database.
	Size string `json:"size"`
	// StorageClassName is the name of the storage class that will be
	// used to provision the persistent volume.
	StorageClassName *string `json:"storageClassName,omitempty"`
}

// DexIdentityProviderSpec defines the desired state of the Dex idP server.
type DexIdentityProviderSpec struct {
	// Image is the Dex IdP image to use.
	Image string `json:"image"`
	// Replicas is the optional number of replicas of the Dex IdP server to run.
	// Only supported if using postgresql storage.
	Replicas *int32 `json:"replicas,omitempty"`
	// ClientCertificateSecretRef is an optional reference to a secret containing a client
	// certificate that the operator can use for connecting to the Dex IdP API server.
	ClientCertificateSecretRef *reference.LocalSecretReference `json:"clientCertificateSecretRef,omitempty"`
	// Issuer is the base path of Dex and the external name of the OpenID
	// Connect service. This is the canonical URL that all clients MUST use
	// to refer to Dex.
	Issuer string `json:"issuer"`
	// Storage configures the storage for Dex.
	Storage DexIdentityProviderStorageSpec `json:"storage"`
	// Web holds configuration for the web server.
	Web DexIdentityProviderWebSpec `json:"web"`
	// GRPC holds configuration for the gRPC server.
	GRPC DexIdentityProviderGRPCSpec `json:"grpc"`
	// OAuth2 holds configuration for OAuth2.
	OAuth2 *DexIdentityProviderOAuth2Spec `json:"oauth2,omitempty"`
	// Expiry holds configuration for tokens, signing keys, etc.
	Expiry *DexIdentityProviderExpirySpec `json:"expiry,omitempty"`
	// Frontend holds the server's frontend templates and asset configuration.
	Frontend *DexIdentityProviderFrontendSpec `json:"frontend,omitempty"`
	// Logger holds configuration required to customize logging for dex.
	Logger *DexIdentityProviderLoggerSpec `json:"logger,omitempty"`
	// Connectors holds configuration for connectors.
	// +kubebuilder:validation:MinItems=1
	Connectors []DexIdentityProviderConnectorSpec `json:"connectors"`
	// LocalStorage configures local persistent storage for the Dex container.
	// This is useful when using a SQLite database.
	LocalStorage *DexIdentityProviderLocalStorageSpec `json:"localStorage,omitempty"`
}

// DexIdentityProviderPhase is the current state of the Dex idP server.
type DexIdentityProviderPhase string

const (
	DexIdentityProviderPhasePending DexIdentityProviderPhase = "Pending"
	DexIdentityProviderPhaseReady   DexIdentityProviderPhase = "Ready"
	DexIdentityProviderPhaseFailed  DexIdentityProviderPhase = "Failed"
)

type DexIdentityProviderConditionType string

const (
	DexIdentityProviderConditionTypePending DexIdentityProviderConditionType = "Pending"
	DexIdentityProviderConditionTypeReady   DexIdentityProviderConditionType = "Ready"
	DexIdentityProviderConditionTypeFailed  DexIdentityProviderConditionType = "Failed"
)

// DexIdentityProviderStatus defines the observed state of the Dex idP server.
type DexIdentityProviderStatus struct {
	// Phase is the current state of the Dex idP server.
	Phase DexIdentityProviderPhase `json:"phase,omitempty"`
	// ObservedGeneration is the most recent generation observed for this DexIdentityProvider by the controller.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// Conditions represents the latest available observations of an DexIdentityProvider's current state.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// ClientRefs is a list of clients that are using this DexIdentityProvider.
	ClientRefs []api.DexOAuth2ClientReference `json:"clientRefs,omitempty"`
}

// DexIdentityProvider is a Dex IdP server.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=idp
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type DexIdentityProvider struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DexIdentityProviderSpec   `json:"spec,omitempty"`
	Status DexIdentityProviderStatus `json:"status,omitempty"`
}

// DexIdentityProviderList contains a list of DexIdentityProvider
// +kubebuilder:object:root=true
type DexIdentityProviderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DexIdentityProvider `json:"items"`
}

func (d *DexIdentityProvider) ResolveReferences(ctx context.Context, reader client.Reader, scheme *runtime.Scheme) error {
	if d.Spec.ClientCertificateSecretRef != nil {
		if _, err := d.Spec.ClientCertificateSecretRef.Resolve(ctx, reader, scheme, d); err != nil {
			return err
		}
	}

	if d.Spec.Web.CertificateSecretRef != nil {
		if _, err := d.Spec.Web.CertificateSecretRef.Resolve(ctx, reader, scheme, d); err != nil {
			return err
		}
	}

	if d.Spec.GRPC.CertificateSecretRef != nil {
		if _, err := d.Spec.GRPC.CertificateSecretRef.Resolve(ctx, reader, scheme, d); err != nil {
			return err
		}
	}

	if d.Spec.GRPC.ClientCASecretRef != nil {
		if _, err := d.Spec.GRPC.ClientCASecretRef.Resolve(ctx, reader, scheme, d); err != nil {
			return err
		}
	}

	if d.Spec.Storage.Type == DexIdentityProviderStorageTypePostgres && d.Spec.Storage.Postgres != nil {
		if _, err := d.Spec.Storage.Postgres.CredentialsSecretRef.Resolve(ctx, reader, scheme, d); err != nil {
			return err
		}

		if d.Spec.Storage.Postgres.SSL != nil {
			if d.Spec.Storage.Postgres.SSL.CASecretRef != nil {
				if _, err := d.Spec.Storage.Postgres.SSL.CASecretRef.Resolve(ctx, reader, scheme, d); err != nil {
					return err
				}
			}

			if d.Spec.Storage.Postgres.SSL.ClientCertificateSecretRef != nil {
				if _, err := d.Spec.Storage.Postgres.SSL.ClientCertificateSecretRef.Resolve(ctx, reader, scheme, d); err != nil {
					return err
				}
			}
		}
	}

	for _, connector := range d.Spec.Connectors {
		if connector.Type == DexIdentityProviderConnectorTypeLDAP && connector.LDAP != nil {
			if _, err := connector.LDAP.BindPasswordSecretRef.Resolve(ctx, reader, scheme, d); err != nil {
				return err
			}

			if connector.LDAP.CASecretRef != nil {
				if _, err := connector.LDAP.CASecretRef.Resolve(ctx, reader, scheme, d); err != nil {
					return err
				}
			}

			if connector.LDAP.ClientCertificateSecretRef != nil {
				if _, err := connector.LDAP.ClientCertificateSecretRef.Resolve(ctx, reader, scheme, d); err != nil {
					return err
				}
			}
		} else if connector.Type == DexIdentityProviderConnectorTypeOIDC && connector.OIDC != nil {
			if _, err := connector.OIDC.ClientSecretRef.Resolve(ctx, reader, scheme, d); err != nil {
				return err
			}

			if connector.OIDC.CASecretRef != nil {
				if _, err := connector.OIDC.CASecretRef.Resolve(ctx, reader, scheme, d); err != nil {
					return err
				}
			}
		} else {
			return fmt.Errorf("invalid connector: %s", connector.Type)
		}
	}

	return nil
}

func init() {
	SchemeBuilder.Register(&DexIdentityProvider{}, &DexIdentityProviderList{})
}
