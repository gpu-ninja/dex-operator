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

	"github.com/gpu-ninja/dex-operator/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// DexOAuth2ClientSpec defines the desired state of the OAuth2 client.
type DexOAuth2ClientSpec struct {
	// IdentityProviderRef is a reference to the identity provider which this
	// client is associated with.
	IdentityProviderRef api.DexIdentityProviderReference `json:"identityProviderRef"`
	// SecretName is the name of the secret that will be created to store the
	// OAuth2 client id and client secret.
	SecretName string `json:"secretName"`
	// RedirectURIs is a list of allowed redirect URLs for the client.
	RedirectURIs []string `json:"redirectURIs,omitempty"`
	// TrustedPeers are a list of peers which can issue tokens on this client's
	// behalf using the dynamic "oauth2:server:client_id:(client_id)" scope.
	// If a peer makes such a request, this client's ID will appear as the ID Token's audience.
	TrustedPeers []string `json:"trustedPeers,omitempty"`
	// Public indicates that this client is a public client, such as a mobile app.
	// Public clients must use either use a redirectURL 127.0.0.1:X or "urn:ietf:wg:oauth:2.0:oob".
	Public bool `json:"public,omitempty"`
	// Name is the human-readable name of the client.
	Name string `json:"name,omitempty"`
	// LogoURL is the URL to a logo for the client.
	LogoURL string `json:"logoURL,omitempty"`
}

type DexOAuth2ClientPhase string

const (
	// DexOAuth2ClientPhasePending indicates that the OAuth2 client is pending.
	DexOAuth2ClientPhasePending DexOAuth2ClientPhase = "Pending"
	// DexOAuth2ClientPhaseReady indicates that the OAuth2 client is ready.
	DexOAuth2ClientPhaseReady DexOAuth2ClientPhase = "Ready"
	// DexOAuth2ClientPhaseFailed indicates that the OAuth2 client has failed.
	DexOAuth2ClientPhaseFailed DexOAuth2ClientPhase = "Failed"
)

// DexOAuth2ClientStatus defines the observed state of the OAuth2 client.
type DexOAuth2ClientStatus struct {
	// Phase is the current phase of the OAuth2 client.
	Phase DexOAuth2ClientPhase `json:"phase,omitempty"`
	// ObservedGeneration is the most recent generation observed for this OAuth2 client by the controller.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// Reason is a human readable message indicating details about why the OAuth2 client is in this condition.
	Reason string `json:"reason,omitempty"`
}

// DexOAuth2Client is an OAuth2 client registered with Dex.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=oac
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type DexOAuth2Client struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DexOAuth2ClientSpec   `json:"spec,omitempty"`
	Status DexOAuth2ClientStatus `json:"status,omitempty"`
}

// DexOAuth2ClientList contains a list of DexOAuth2Client
// +kubebuilder:object:root=true
type DexOAuth2ClientList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DexOAuth2Client `json:"items"`
}

func (d *DexOAuth2Client) ResolveReferences(ctx context.Context, reader client.Reader, scheme *runtime.Scheme) (bool, error) {
	_, ok, err := d.Spec.IdentityProviderRef.Resolve(ctx, reader, scheme, d)
	if !ok || err != nil {
		return ok, err
	}

	return true, nil
}

func init() {
	SchemeBuilder.Register(&DexOAuth2Client{}, &DexOAuth2ClientList{})
}
