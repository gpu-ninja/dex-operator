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

package controller_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	dexv1alpha1 "github.com/gpu-ninja/dex-operator/api/v1alpha1"
	"github.com/gpu-ninja/dex-operator/internal/controller"
	fakeutils "github.com/gpu-ninja/operator-utils/fake"
	"github.com/gpu-ninja/operator-utils/reference"
	"github.com/gpu-ninja/operator-utils/zaplogr"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestDexIdentityProviderReconciler(t *testing.T) {
	ctrl.SetLogger(zaplogr.New(zaptest.NewLogger(t)))

	scheme := runtime.NewScheme()

	err := corev1.AddToScheme(scheme)
	require.NoError(t, err)

	err = appsv1.AddToScheme(scheme)
	require.NoError(t, err)

	err = monitoringv1.AddToScheme(scheme)
	require.NoError(t, err)

	err = dexv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	idp := &dexv1alpha1.DexIdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: dexv1alpha1.DexIdentityProviderSpec{
			Issuer: "http://127.0.0.1:8080/dex",
			Storage: dexv1alpha1.DexIdentityProviderStorageSpec{
				Type: dexv1alpha1.DexIdentityProviderStorageTypeSqlite3,
				Sqlite3: &dexv1alpha1.DexIdentityProviderStorageSqlite3Spec{
					File: "var/sqlite/dex.db",
				},
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
			VolumeClaimTemplates: []corev1.PersistentVolumeClaim{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "dex",
					},
					Spec: corev1.PersistentVolumeClaimSpec{
						StorageClassName: ptr.To("local-path"),
						AccessModes: []corev1.PersistentVolumeAccessMode{
							corev1.ReadWriteMany,
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceStorage: resource.MustParse("1Gi"),
							},
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

	subResourceClient := fakeutils.NewSubResourceClient(scheme)

	interceptorFuncs := interceptor.Funcs{
		SubResource: func(client client.WithWatch, subResource string) client.SubResourceClient {
			return subResourceClient
		},
	}

	r := &controller.DexIdentityProviderReconciler{
		Scheme: scheme,
	}

	ctx := context.Background()

	t.Run("Create or Update", func(t *testing.T) {
		eventRecorder := record.NewFakeRecorder(2)
		r.Recorder = eventRecorder

		subResourceClient.Reset()

		r.Client = fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(idp, ldapCA, ldapBindPassword).
			WithStatusSubresource(idp).
			WithInterceptorFuncs(interceptorFuncs).
			Build()

		resp, err := r.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      idp.Name,
				Namespace: idp.Namespace,
			},
		})
		require.NoError(t, err)
		assert.NotZero(t, resp.RequeueAfter)

		require.Len(t, eventRecorder.Events, 1)
		event := <-eventRecorder.Events
		assert.Equal(t, "Normal Pending Waiting for statefulset to become ready", event)

		updatedIDP := idp.DeepCopy()
		err = subResourceClient.Get(ctx, idp, updatedIDP)
		require.NoError(t, err)

		assert.Equal(t, dexv1alpha1.DexIdentityProviderPhasePending, updatedIDP.Status.Phase)
		assert.Len(t, updatedIDP.Status.Conditions, 1)

		var webService corev1.Service
		err = r.Client.Get(ctx, types.NamespacedName{
			Name:      "dex-" + idp.Name,
			Namespace: idp.Namespace,
		}, &webService)
		require.NoError(t, err)

		var apiService corev1.Service
		err = r.Client.Get(ctx, types.NamespacedName{
			Name:      "dex-" + idp.Name + "-api",
			Namespace: idp.Namespace,
		}, &apiService)
		require.NoError(t, err)

		var metricsService corev1.Service
		err = r.Client.Get(ctx, types.NamespacedName{
			Name:      "dex-" + idp.Name + "-metrics",
			Namespace: idp.Namespace,
		}, &metricsService)
		require.NoError(t, err)

		var serviceMonitor monitoringv1.ServiceMonitor
		err = r.Client.Get(ctx, types.NamespacedName{
			Name:      "dex-" + idp.Name,
			Namespace: idp.Namespace,
		}, &serviceMonitor)
		require.NoError(t, err)

		var sts appsv1.StatefulSet
		err = r.Client.Get(ctx, types.NamespacedName{
			Name:      "dex-" + idp.Name,
			Namespace: idp.Namespace,
		}, &sts)
		require.NoError(t, err)

		var configVolume *corev1.Volume
		for _, volume := range sts.Spec.Template.Spec.Volumes {
			if volume.Name == "config" {
				configVolume = &volume
				break
			}
		}
		require.NotNil(t, configVolume)

		var configSecret corev1.Secret
		err = r.Client.Get(ctx, types.NamespacedName{
			Name:      configVolume.VolumeSource.Secret.SecretName,
			Namespace: idp.Namespace,
		}, &configSecret)
		require.NoError(t, err)

		assert.NotEmpty(t, configSecret.Data["config.yaml"])

		sts.Status.ReadyReplicas = *sts.Spec.Replicas

		r.Client = fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(updatedIDP, ldapCA, ldapBindPassword, &sts).
			WithStatusSubresource(updatedIDP, &sts).
			WithInterceptorFuncs(interceptorFuncs).
			Build()

		resp, err = r.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      idp.Name,
				Namespace: idp.Namespace,
			},
		})
		require.NoError(t, err)
		assert.Zero(t, resp)

		require.Len(t, eventRecorder.Events, 1)
		event = <-eventRecorder.Events
		assert.Equal(t, "Normal Created Successfully created", event)

		updatedIDP = idp.DeepCopy()
		err = subResourceClient.Get(ctx, idp, updatedIDP)
		require.NoError(t, err)

		assert.Equal(t, dexv1alpha1.DexIdentityProviderPhaseReady, updatedIDP.Status.Phase)
		assert.Len(t, updatedIDP.Status.Conditions, 2)
	})

	t.Run("Delete", func(t *testing.T) {
		deletingIDP := idp.DeepCopy()
		deletingIDP.DeletionTimestamp = &metav1.Time{Time: metav1.Now().Add(-1 * time.Second)}
		deletingIDP.Finalizers = []string{controller.FinalizerName}

		eventRecorder := record.NewFakeRecorder(2)
		r.Recorder = eventRecorder

		r.Client = fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(deletingIDP, ldapCA, ldapBindPassword).
			WithStatusSubresource(deletingIDP).
			Build()

		resp, err := r.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      idp.Name,
				Namespace: idp.Namespace,
			},
		})
		require.NoError(t, err)
		assert.Zero(t, resp)

		assert.Len(t, eventRecorder.Events, 0)
	})

	t.Run("References Not Resolvable", func(t *testing.T) {
		eventRecorder := record.NewFakeRecorder(2)
		r.Recorder = eventRecorder

		subResourceClient.Reset()

		r.Client = fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(idp). // note the missing secrets
			WithStatusSubresource(idp).
			WithInterceptorFuncs(interceptorFuncs).
			Build()

		resp, err := r.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      idp.Name,
				Namespace: idp.Namespace,
			},
		})
		require.NoError(t, err)
		assert.NotZero(t, resp.RequeueAfter)

		require.Len(t, eventRecorder.Events, 1)
		event := <-eventRecorder.Events
		assert.Equal(t, "Warning NotReady Not all references are resolvable", event)

		updatedIDP := idp.DeepCopy()
		err = subResourceClient.Get(ctx, idp, updatedIDP)
		require.NoError(t, err)

		assert.Equal(t, dexv1alpha1.DexIdentityProviderPhasePending, updatedIDP.Status.Phase)
		assert.Len(t, updatedIDP.Status.Conditions, 1)
	})

	t.Run("Failure", func(t *testing.T) {
		eventRecorder := record.NewFakeRecorder(2)
		r.Recorder = eventRecorder

		failOnSecrets := interceptorFuncs
		failOnSecrets.Get = func(ctx context.Context, client client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*corev1.Secret); ok {
				return fmt.Errorf("bang")
			}

			return client.Get(ctx, key, obj, opts...)
		}

		subResourceClient.Reset()

		r.Client = fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(idp, ldapCA, ldapBindPassword).
			WithStatusSubresource(idp).
			WithInterceptorFuncs(failOnSecrets).
			Build()

		_, err := r.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      idp.Name,
				Namespace: idp.Namespace,
			},
		})
		require.Error(t, err)

		require.Len(t, eventRecorder.Events, 1)
		event := <-eventRecorder.Events
		assert.Equal(t, "Warning Failed Failed to reconcile dex config: failed to get object: bang", event)

		updatedIDP := idp.DeepCopy()
		err = subResourceClient.Get(ctx, idp, updatedIDP)
		require.NoError(t, err)

		assert.Equal(t, dexv1alpha1.DexIdentityProviderPhaseFailed, updatedIDP.Status.Phase)
	})
}
