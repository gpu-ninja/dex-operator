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

	dexapi "github.com/dexidp/dex/api/v2"
	"github.com/gpu-ninja/dex-operator/api"
	dexv1alpha1 "github.com/gpu-ninja/dex-operator/api/v1alpha1"
	"github.com/gpu-ninja/dex-operator/internal/constants"
	"github.com/gpu-ninja/dex-operator/internal/controller"
	"github.com/gpu-ninja/dex-operator/internal/dex"
	fakeutils "github.com/gpu-ninja/operator-utils/fake"
	"github.com/gpu-ninja/operator-utils/zaplogr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestDexOAuth2ClientReconciler(t *testing.T) {
	ctrl.SetLogger(zaplogr.New(zaptest.NewLogger(t)))

	scheme := runtime.NewScheme()

	err := corev1.AddToScheme(scheme)
	require.NoError(t, err)

	err = dexv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	oauth2Client := &dexv1alpha1.DexOAuth2Client{
		ObjectMeta: ctrl.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: dexv1alpha1.DexOAuth2ClientSpec{
			IdentityProviderRef: api.DexIdentityProviderReference{
				Name: "test",
			},
			SecretName: "oauth2-client-secret",
			RedirectURIs: []string{
				"https://client.example.com/callback",
			},
		},
	}

	idp := &dexv1alpha1.DexIdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: dexv1alpha1.DexIdentityProviderSpec{},
		Status: dexv1alpha1.DexIdentityProviderStatus{
			Phase: dexv1alpha1.DexIdentityProviderPhaseReady,
		},
	}

	generatedClientSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "oauth2-client-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"client_id":     []byte("id"),
			"client_secret": []byte("secret"),
		},
	}

	subResourceClient := fakeutils.NewSubResourceClient(scheme)

	interceptorFuncs := interceptor.Funcs{
		SubResource: func(client client.WithWatch, subResource string) client.SubResourceClient {
			return subResourceClient
		},
	}

	r := &controller.DexOAuth2ClientReconciler{
		Scheme: scheme,
	}

	ctx := context.Background()

	t.Run("Create or Update", func(t *testing.T) {
		eventRecorder := record.NewFakeRecorder(2)
		r.EventRecorder = eventRecorder

		subResourceClient.Reset()

		r.Client = fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(oauth2Client, idp).
			WithStatusSubresource(oauth2Client, idp).
			WithInterceptorFuncs(interceptorFuncs).
			Build()

		var m mock.Mock
		r.DexClientBuilder = dex.NewFakeClientBuilder(&m)

		m.On("UpdateClient", mock.Anything, mock.Anything, mock.Anything).
			Return(&dexapi.UpdateClientResp{
				NotFound: true,
			}, nil)

		m.On("CreateClient", mock.Anything, mock.Anything, mock.Anything).
			Return(&dexapi.CreateClientResp{}, nil)

		resp, err := r.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      oauth2Client.Name,
				Namespace: oauth2Client.Namespace,
			},
		})
		require.NoError(t, err)
		assert.Zero(t, resp)

		require.Len(t, eventRecorder.Events, 1)
		event := <-eventRecorder.Events
		assert.Equal(t, "Normal Created Successfully created", event)

		updatedOAuth2Client := oauth2Client.DeepCopy()
		err = subResourceClient.Get(ctx, oauth2Client, updatedOAuth2Client)
		require.NoError(t, err)

		assert.Equal(t, dexv1alpha1.DexOAuth2ClientPhaseReady, updatedOAuth2Client.Status.Phase)
	})

	t.Run("Delete", func(t *testing.T) {
		deletingOauth2Client := oauth2Client.DeepCopy()
		deletingOauth2Client.DeletionTimestamp = &metav1.Time{Time: metav1.Now().Add(-1 * time.Second)}
		deletingOauth2Client.Finalizers = []string{constants.FinalizerName}

		eventRecorder := record.NewFakeRecorder(2)
		r.EventRecorder = eventRecorder

		subResourceClient.Reset()

		r.Client = fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(deletingOauth2Client, idp, generatedClientSecret).
			WithStatusSubresource(deletingOauth2Client).
			WithInterceptorFuncs(interceptorFuncs).
			Build()

		var m mock.Mock
		r.DexClientBuilder = dex.NewFakeClientBuilder(&m)

		m.On("DeleteClient", mock.Anything, mock.Anything, mock.Anything).
			Return(&dexapi.DeleteClientResp{}, nil)

		resp, err := r.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      idp.Name,
				Namespace: idp.Namespace,
			},
		})
		require.NoError(t, err)
		assert.Zero(t, resp)

		assert.Len(t, eventRecorder.Events, 0)

		m.AssertCalled(t, "DeleteClient", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("References Not Resolvable", func(t *testing.T) {
		eventRecorder := record.NewFakeRecorder(2)
		r.EventRecorder = eventRecorder

		subResourceClient.Reset()

		r.Client = fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(oauth2Client).
			WithStatusSubresource(oauth2Client).
			WithInterceptorFuncs(interceptorFuncs).
			Build()

		resp, err := r.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      oauth2Client.Name,
				Namespace: oauth2Client.Namespace,
			},
		})
		require.NoError(t, err)
		assert.NotZero(t, resp.RequeueAfter)

		require.Len(t, eventRecorder.Events, 1)
		event := <-eventRecorder.Events
		assert.Equal(t, "Warning NotReady Not all references are resolvable", event)

		updatedOAuth2Client := oauth2Client.DeepCopy()
		err = subResourceClient.Get(ctx, oauth2Client, updatedOAuth2Client)
		require.NoError(t, err)

		assert.Equal(t, dexv1alpha1.DexOAuth2ClientPhasePending, updatedOAuth2Client.Status.Phase)
	})

	t.Run("Identity Provider Not Ready", func(t *testing.T) {
		eventRecorder := record.NewFakeRecorder(2)
		r.EventRecorder = eventRecorder

		subResourceClient.Reset()

		notReadyIDP := idp.DeepCopy()
		notReadyIDP.Status.Phase = dexv1alpha1.DexIdentityProviderPhasePending

		r.Client = fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(oauth2Client, notReadyIDP).
			WithStatusSubresource(oauth2Client, notReadyIDP).
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
		assert.Equal(t, "Warning NotReady Referenced identity provider is not ready", event)

		updatedOAuth2Client := oauth2Client.DeepCopy()
		err = subResourceClient.Get(ctx, oauth2Client, updatedOAuth2Client)
		require.NoError(t, err)

		assert.Equal(t, dexv1alpha1.DexOAuth2ClientPhasePending, updatedOAuth2Client.Status.Phase)
	})

	t.Run("Failure", func(t *testing.T) {
		eventRecorder := record.NewFakeRecorder(2)
		r.EventRecorder = eventRecorder

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
			WithObjects(oauth2Client, idp).
			WithStatusSubresource(oauth2Client).
			WithInterceptorFuncs(failOnSecrets).
			Build()

		resp, err := r.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      oauth2Client.Name,
				Namespace: oauth2Client.Namespace,
			},
		})
		require.NoError(t, err)
		assert.Zero(t, resp)

		require.Len(t, eventRecorder.Events, 1)
		event := <-eventRecorder.Events
		assert.Equal(t, "Warning Failed Failed to get client secret", event)

		updatedOAuth2Client := oauth2Client.DeepCopy()
		err = subResourceClient.Get(ctx, oauth2Client, updatedOAuth2Client)
		require.NoError(t, err)

		assert.Equal(t, dexv1alpha1.DexOAuth2ClientPhaseFailed, updatedOAuth2Client.Status.Phase)
	})
}
