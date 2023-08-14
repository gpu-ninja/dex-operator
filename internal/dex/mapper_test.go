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

package dex_test

import (
	"context"
	"os"
	"testing"

	dexv1alpha1 "github.com/gpu-ninja/dex-operator/api/v1alpha1"
	"github.com/gpu-ninja/dex-operator/internal/dex"
	"github.com/gpu-ninja/operator-utils/reference"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestConfigFromCR(t *testing.T) {
	scheme := runtime.NewScheme()
	err := corev1.AddToScheme(scheme)
	require.NoError(t, err)

	err = dexv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	idp := &dexv1alpha1.DexIdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: dexv1alpha1.DexIdentityProviderSpec{
			Issuer: "http://127.0.0.1:5556/dex",
			Storage: dexv1alpha1.DexIdentityProviderStorageSpec{
				Type: dexv1alpha1.DexIdentityProviderStorageTypeSqlite3,
				Sqlite3: &dexv1alpha1.DexIdentityProviderStorageSqlite3Spec{
					File: "var/sqlite/dex.db",
				},
			},
			Web: dexv1alpha1.DexIdentityProviderWebSpec{
				HTTP: "127.0.0.1:5556",
			},
			GRPC: dexv1alpha1.DexIdentityProviderGRPCSpec{
				Addr: "127.0.0.1:5557",
			},
			Connectors: []dexv1alpha1.DexIdentityProviderConnectorSpec{
				{
					Type: dexv1alpha1.DexIdentityProviderConnectorTypeLDAP,
					ID:   "ldap",
					Name: "LDAP",
					LDAP: &dexv1alpha1.DexIdentityProviderConnectorLDAPSpec{
						Host: "ldap.example.com:636",
						CASecretRef: &reference.LocalSecretReference{
							Name: "ldap-ca",
						},
						BindUsername: "cn=admin,dc=example,dc=com",
						BindPasswordSecretRef: reference.LocalSecretReference{
							Name: "ldap-bind-password",
						},
						UsernamePrompt: "SSO Username",
						UserSearch: dexv1alpha1.DexIdentityProviderConnectorLDAPUserSearchSpec{
							BaseDN:                "ou=users,dc=example,dc=com",
							Filter:                "(objectClass=person)",
							Username:              "uid",
							IDAttr:                "uid",
							EmailAttr:             "mail",
							NameAttr:              "name",
							PreferredUsernameAttr: "uid",
						},
						GroupSearch: dexv1alpha1.DexIdentityProviderConnectorLDAPGroupSearchSpec{
							BaseDN: "cn=groups,dc=example,dc=com",
							Filter: "(objectClass=group)",
							UserMatchers: []dexv1alpha1.DexIdentityProviderConnectorLDAPGroupSearchUserMatcher{
								{
									UserAttr:  "uid",
									GroupAttr: "member",
								},
							},
							NameAttr: "name",
						},
					},
				},
			},
		},
	}

	ldapCA := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ldap-ca",
			Namespace: "default",
		},
		Type: corev1.SecretTypeTLS,
		StringData: map[string]string{
			"ca.crt":  "",
			"tls.crt": "",
			"tls.key": "",
		},
	}

	ldapBindPassword := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ldap-bind-password",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"password": []byte("password"),
		},
	}

	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(idp, ldapCA, ldapBindPassword).Build()

	ctx := context.Background()

	config, err := dex.ConfigFromCR(ctx, reader, scheme, idp)

	assert.NoError(t, err)

	actual, err := yaml.Marshal(config)
	require.NoError(t, err)

	expected, err := os.ReadFile("testdata/config.yaml")
	require.NoError(t, err)

	assert.YAMLEq(t, string(expected), string(actual))
}
