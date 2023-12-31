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
	"strings"

	"github.com/gpu-ninja/dex-operator/api"
	"github.com/gpu-ninja/operator-utils/reference"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Duration is a valid time duration that can be parsed by Prometheus model.ParseDuration() function.
// Supported units: y, w, d, h, m, s, ms
// Examples: `30s`, `1m`, `1h20m15s`, `15d`
// +kubebuilder:validation:Pattern:="^(0|(([0-9]+)y)?(([0-9]+)w)?(([0-9]+)d)?(([0-9]+)h)?(([0-9]+)m)?(([0-9]+)s)?(([0-9]+)ms)?)$"
type Duration string

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

// DexIdentityProviderLoggerSpec allows customizing logging for Dex.
type DexIdentityProviderLoggerSpec struct {
	// Level sets logging level severity.
	Level string `json:"level,omitempty"`
	// Format specifies the format to be used for logging.
	Format string `json:"format,omitempty"`
}

// DexIdentityProviderMetricsSpec holds configuration for metrics.
type DexIdentityProviderMetricsSpec struct {
	// Enabled enables Prometheus metric scraping.
	Enabled bool `json:"enabled,omitempty"`
	// Interval at which metrics should be scraped
	// If not specified Prometheus' global scrape interval is used.
	Interval Duration `json:"interval,omitempty"`
}

// DexIdentityProviderGRPCSpec holds configuration for the Dex API gRPC server.
type DexIdentityProviderGRPCSpec struct {
	// CertificateSecretRef is an optional reference to a secret containing the TLS certificate and key
	// to use for the Dex API gRPC server.
	CertificateSecretRef *reference.LocalSecretReference `json:"certificateSecretRef,omitempty"`
	// ClientCASecretRef is an optional reference to a secret containing the client CA.
	ClientCASecretRef *reference.LocalSecretReference `json:"clientCASecretRef,omitempty"`
	// Reflection enables gRPC server reflection.
	Reflection bool `json:"reflection,omitempty"`
	// Annotations is an optional map of additional annotations to add to the Dex API gRPC service.
	Annotations map[string]string `json:"annotations,omitempty"`
}

// DexIdentityProviderWebSpec holds configuration for the web server.
type DexIdentityProviderWebSpec struct {
	// CertificateSecretRef is an optional reference to a secret containing the TLS certificate and key
	// to use for HTTPS.
	CertificateSecretRef *reference.LocalSecretReference `json:"certificateSecretRef,omitempty"`
	// AllowedOrigins is a list of allowed origins for CORS requests.
	AllowedOrigins []string `json:"allowedOrigins,omitempty"`
	// Annotations is an optional map of additional annotations to add to the web service.
	Annotations map[string]string `json:"annotations,omitempty"`
}

// DexIdentityProviderIngressPathSpec is the ingress path configuration for a Dex identity provider.
type DexIdentityProviderIngressPathSpec struct {
	// Path is matched against the path of an incoming request.
	Path string `json:"path"`
	// PathType determines the interpretation of the Path matching.
	// +kubebuilder:validation:Enum=Exact;Prefix;ImplementationSpecific
	PathType networkingv1.PathType `json:"pathType"`
}

// DexIdentityProviderIngressHostSpec is the ingress host configuration for a Dex identity provider.
type DexIdentityProviderIngressHostSpec struct {
	// Host is the host to route traffic to the Dex identity provider.
	Host string `json:"host"`
	// Paths is a list of paths to route traffic to the Dex identity provider.
	Paths []DexIdentityProviderIngressPathSpec `json:"paths"`
}

// DexIdentityProviderIngressSpec is the ingress configuration for a Dex identity provider.
type DexIdentityProviderIngressSpec struct {
	// Enabled enables ingress for the Dex identity provider.
	Enabled bool `json:"enabled"`
	// IngressClassName is the optional ingress class to use for the Dex identity provider.
	IngressClassName *string `json:"ingressClassName,omitempty"`
	// Annotations is an optional map of additional annotations to add to the ingress.
	Annotations map[string]string `json:"annotations,omitempty"`
	// Hosts is a list of hosts and paths to route traffic to the Dex identity provider.
	Hosts []DexIdentityProviderIngressHostSpec `json:"hosts"`
	// TLS is an optional list of TLS configurations for the ingress.
	TLS []networkingv1.IngressTLS `json:"tls,omitempty"`
}

// DexIdentityProviderSpec defines the desired state of the Dex identity provider.
type DexIdentityProviderSpec struct {
	// Image is the Dex image to use.
	Image string `json:"image"`
	// Replicas is the optional number of replicas of the Dex identity provider pod to run.
	// Only supported if using postgresql storage.
	Replicas *int32 `json:"replicas,omitempty"`
	// ClientCertificateSecretRef is an optional reference to a secret containing a client
	// certificate that the operator can use for connecting to the Dex API gRPC server.
	ClientCertificateSecretRef *reference.LocalSecretReference `json:"clientCertificateSecretRef,omitempty"`
	// Issuer is the base path of Dex and the external name of the OpenID
	// Connect service. This is the canonical URL that all clients MUST use
	// to refer to Dex.
	Issuer string `json:"issuer"`
	// Storage configures the storage for Dex.
	Storage DexIdentityProviderStorageSpec `json:"storage"`
	// OAuth2 holds configuration for OAuth2.
	OAuth2 *DexIdentityProviderOAuth2Spec `json:"oauth2,omitempty"`
	// Expiry holds configuration for tokens, signing keys, etc.
	Expiry *DexIdentityProviderExpirySpec `json:"expiry,omitempty"`
	// Frontend holds the web server's frontend templates and asset configuration.
	Frontend *DexIdentityProviderFrontendSpec `json:"frontend,omitempty"`
	// Logger holds configuration required to customize logging for dex.
	Logger *DexIdentityProviderLoggerSpec `json:"logger,omitempty"`
	// Metrics holds configuration for metrics.
	Metrics *DexIdentityProviderMetricsSpec `json:"metrics,omitempty"`
	// GRPC holds configuration for the Dex API gRPC server.
	GRPC DexIdentityProviderGRPCSpec `json:"grpc"`
	// Web holds configuration for the web server.
	Web DexIdentityProviderWebSpec `json:"web"`
	// Connectors holds configuration for connectors.
	Connectors []DexIdentityProviderConnectorSpec `json:"connectors,omitempty"`
	// Ingress is the optional ingress configuration for the Dex identity provider.
	Ingress *DexIdentityProviderIngressSpec `json:"ingress,omitempty"`
	// VolumeMounts are volume mounts for the Dex identity provider container.
	VolumeMounts []corev1.VolumeMount `json:"volumeMounts,omitempty"`
	// VolumeClaimTemplates are volume claim templates for the Dex identity provider pod.
	VolumeClaimTemplates []corev1.PersistentVolumeClaim `json:"volumeClaimTemplates,omitempty"`
	// Resources allows specifying the resource requirements for the Dex identity provider container.
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
}

// DexIdentityProviderPhase is the current state of the Dex identity provider.
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

// DexIdentityProviderStatus defines the observed state of the Dex identity provider.
type DexIdentityProviderStatus struct {
	// Phase is the current state of the Dex identity provider.
	Phase DexIdentityProviderPhase `json:"phase,omitempty"`
	// ObservedGeneration is the most recent generation observed for this DexIdentityProvider by the controller.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// Conditions represents the latest available observations of an DexIdentityProvider's current state.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// ClientRefs is a list of clients that are using this DexIdentityProvider.
	ClientRefs []api.DexOAuth2ClientReference `json:"clientRefs,omitempty"`
}

// DexIdentityProvider is a Dex identity provider instance.
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

func (d *DexIdentityProvider) ResolveReferences(ctx context.Context, reader client.Reader, scheme *runtime.Scheme) (bool, error) {
	if d.Spec.ClientCertificateSecretRef != nil {
		_, ok, err := d.Spec.ClientCertificateSecretRef.Resolve(ctx, reader, scheme, d)
		if !ok || err != nil {
			return ok, err
		}
	}

	if d.Spec.Web.CertificateSecretRef != nil {
		_, ok, err := d.Spec.Web.CertificateSecretRef.Resolve(ctx, reader, scheme, d)
		if !ok || err != nil {
			return ok, err
		}
	}

	if d.Spec.GRPC.CertificateSecretRef != nil {
		_, ok, err := d.Spec.GRPC.CertificateSecretRef.Resolve(ctx, reader, scheme, d)
		if !ok || err != nil {
			return ok, err
		}
	}

	if d.Spec.GRPC.ClientCASecretRef != nil {
		_, ok, err := d.Spec.GRPC.ClientCASecretRef.Resolve(ctx, reader, scheme, d)
		if !ok || err != nil {
			return ok, err
		}
	}

	if d.Spec.Storage.Type == DexIdentityProviderStorageTypePostgres && d.Spec.Storage.Postgres != nil {
		_, ok, err := d.Spec.Storage.Postgres.CredentialsSecretRef.Resolve(ctx, reader, scheme, d)
		if !ok || err != nil {
			return ok, err
		}

		if d.Spec.Storage.Postgres.SSL != nil {
			if d.Spec.Storage.Postgres.SSL.CASecretRef != nil {
				_, ok, err := d.Spec.Storage.Postgres.SSL.CASecretRef.Resolve(ctx, reader, scheme, d)
				if !ok || err != nil {
					return ok, err
				}
			}

			if d.Spec.Storage.Postgres.SSL.ClientCertificateSecretRef != nil {
				_, ok, err := d.Spec.Storage.Postgres.SSL.ClientCertificateSecretRef.Resolve(ctx, reader, scheme, d)
				if !ok || err != nil {
					return ok, err
				}
			}
		}
	}

	for _, connector := range d.Spec.Connectors {
		if connector.Type == DexIdentityProviderConnectorTypeLDAP && connector.LDAP != nil {
			_, ok, err := connector.LDAP.BindPasswordSecretRef.Resolve(ctx, reader, scheme, d)
			if !ok || err != nil {
				return ok, err
			}

			if connector.LDAP.CASecretRef != nil {
				_, ok, err := connector.LDAP.CASecretRef.Resolve(ctx, reader, scheme, d)
				if !ok || err != nil {
					return ok, err
				}
			}

			if connector.LDAP.ClientCertificateSecretRef != nil {
				_, ok, err := connector.LDAP.ClientCertificateSecretRef.Resolve(ctx, reader, scheme, d)
				if !ok || err != nil {
					return ok, err
				}
			}
		} else if connector.Type == DexIdentityProviderConnectorTypeOIDC && connector.OIDC != nil {
			_, ok, err := connector.OIDC.ClientSecretRef.Resolve(ctx, reader, scheme, d)
			if !ok || err != nil {
				return ok, err
			}

			if connector.OIDC.CASecretRef != nil {
				_, ok, err := connector.OIDC.CASecretRef.Resolve(ctx, reader, scheme, d)
				if !ok || err != nil {
					return ok, err
				}
			}
		} else {
			return false, fmt.Errorf("invalid connector: %s", connector.Type)
		}
	}

	return true, nil
}

func (d *DexIdentityProvider) ChildResourceName(names ...string) string {
	var name string
	if len(names) > 0 {
		name = strings.Join(names, "-")
	}

	if d.Name != "dex" {
		if name == "" {
			return fmt.Sprintf("dex-%s", d.Name)
		}

		return fmt.Sprintf("dex-%s-%s", d.Name, name)
	} else {
		if name == "" {
			return "dex"
		}

		return fmt.Sprintf("dex-%s", name)
	}
}

func init() {
	SchemeBuilder.Register(&DexIdentityProvider{}, &DexIdentityProviderList{})
}
