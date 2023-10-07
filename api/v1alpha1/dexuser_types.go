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

// DexUserSpec defines the desired state of the user.
type DexUserSpec struct {
	// IdentityProviderRef is a reference to the identity provider which this
	// user is associated with.
	IdentityProviderRef api.LocalDexIdentityProviderReference `json:"identityProviderRef"`
	// SecretName is the name of the secret that will be created to store the
	// generated user password.
	SecretName string `json:"secretName"`
	// Email and identifying name of the password. Emails are assumed to be valid and
	// determining that an end-user controls the address is left to an outside application.
	Email string `json:"email"`
}

type DexUserPhase string

const (
	// DexUserPhasePending indicates that the user is pending.
	DexUserPhasePending DexUserPhase = "Pending"
	// DexUserPhaseReady indicates that the user is ready.
	DexUserPhaseReady DexUserPhase = "Ready"
	// DexUserPhaseFailed indicates that the user has failed.
	DexUserPhaseFailed DexUserPhase = "Failed"
)

// DexUserStatus defines the observed state of the user.
type DexUserStatus struct {
	// Phase is the current phase of the user.
	Phase DexUserPhase `json:"phase,omitempty"`
	// ObservedGeneration is the most recent generation observed for this user by the controller.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// Reason is a human readable message indicating details about why the user is in this condition.
	Reason string `json:"reason,omitempty"`
}

// DexUser is a user registered with Dex.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type DexUser struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DexUserSpec   `json:"spec,omitempty"`
	Status DexUserStatus `json:"status,omitempty"`
}

// DexUserList contains a list of DexUser
// +kubebuilder:object:root=true
type DexUserList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DexUser `json:"items"`
}

func (u *DexUser) ResolveReferences(ctx context.Context, reader client.Reader, scheme *runtime.Scheme) (bool, error) {
	_, ok, err := u.Spec.IdentityProviderRef.Resolve(ctx, reader, scheme, u)
	if !ok || err != nil {
		return ok, err
	}

	return true, nil
}

func init() {
	SchemeBuilder.Register(&DexUser{}, &DexUserList{})
}
