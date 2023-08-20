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

package api

import (
	"context"

	"github.com/gpu-ninja/operator-utils/reference"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// +kubebuilder:object:generate=true
type DexIdentityProviderReference struct {
	// Name of the referenced DexIdentityProvider.
	Name string `json:"name"`
	// Namespace is the optional namespace of the referenced DexIdentityProvider.
	Namespace string `json:"namespace,omitempty"`
}

func (ref *DexIdentityProviderReference) Resolve(ctx context.Context, reader client.Reader, scheme *runtime.Scheme, parent runtime.Object) (runtime.Object, bool, error) {
	objRef := &reference.ObjectReference{
		Name:      ref.Name,
		Namespace: ref.Namespace,
		Kind:      "DexIdentityProvider",
	}

	return objRef.Resolve(ctx, reader, scheme, parent)
}

// +kubebuilder:object:generate=true
type DexOAuth2ClientReference struct {
	// Name of the referenced DexOAuth2Client.
	Name string `json:"name"`
	// Namespace is the optional namespace of the referenced DexOAuth2Client.
	Namespace string `json:"namespace,omitempty"`
}

func (ref *DexOAuth2ClientReference) Resolve(ctx context.Context, reader client.Reader, scheme *runtime.Scheme, parent runtime.Object) (runtime.Object, bool, error) {
	objRef := &reference.ObjectReference{
		Name:      ref.Name,
		Namespace: ref.Namespace,
		Kind:      "DexOAuth2Client",
	}

	return objRef.Resolve(ctx, reader, scheme, parent)
}
