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

func TestDexUserReconciler(t *testing.T) {
	ctrl.SetLogger(zaplogr.New(zaptest.NewLogger(t)))

	scheme := runtime.NewScheme()

	err := corev1.AddToScheme(scheme)
	require.NoError(t, err)

	err = dexv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	user := &dexv1alpha1.DexUser{
		ObjectMeta: ctrl.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: dexv1alpha1.DexUserSpec{
			IdentityProviderRef: api.LocalDexIdentityProviderReference{
				Name: "test",
			},
			SecretName: "test-password",
			Email:      "admin@example.com",
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

	subResourceClient := fakeutils.NewSubResourceClient(scheme)

	interceptorFuncs := interceptor.Funcs{
		SubResource: func(client client.WithWatch, subResource string) client.SubResourceClient {
			return subResourceClient
		},
	}

	r := &controller.DexUserReconciler{
		Scheme: scheme,
	}

	ctx := context.Background()

	t.Run("Create or Update", func(t *testing.T) {
		eventRecorder := record.NewFakeRecorder(2)
		r.Recorder = eventRecorder

		subResourceClient.Reset()

		r.Client = fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(user, idp).
			WithStatusSubresource(user, idp).
			WithInterceptorFuncs(interceptorFuncs).
			Build()

		var m mock.Mock
		r.DexClientBuilder = dex.NewFakeClientBuilder(&m)

		m.On("VerifyPassword", mock.Anything, mock.Anything, mock.Anything).
			Return(&dexapi.VerifyPasswordResp{
				NotFound: true,
			}, nil)

		m.On("CreatePassword", mock.Anything, mock.Anything, mock.Anything).
			Return(&dexapi.CreatePasswordResp{}, nil)

		resp, err := r.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      user.Name,
				Namespace: user.Namespace,
			},
		})
		require.NoError(t, err)
		assert.Zero(t, resp)

		require.Len(t, eventRecorder.Events, 1)
		event := <-eventRecorder.Events
		assert.Equal(t, "Normal Ready Successfully created or updated", event)

		updatedUser := user.DeepCopy()
		err = subResourceClient.Get(ctx, user, updatedUser)
		require.NoError(t, err)

		assert.Equal(t, dexv1alpha1.DexUserPhaseReady, updatedUser.Status.Phase)

		secret := corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      user.Spec.SecretName,
				Namespace: user.Namespace,
			},
		}

		err = r.Client.Get(ctx, client.ObjectKeyFromObject(&secret), &secret)
		require.NoError(t, err)

		secret.Data["password"] = []byte("override")

		r.Client = fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(updatedUser, idp, &secret).
			WithStatusSubresource(updatedUser, idp).
			WithInterceptorFuncs(interceptorFuncs).
			Build()

		m = mock.Mock{}
		r.DexClientBuilder = dex.NewFakeClientBuilder(&m)

		m.On("VerifyPassword", mock.Anything, mock.Anything, mock.Anything).
			Return(&dexapi.VerifyPasswordResp{
				Verified: false,
			}, nil)

		m.On("UpdatePassword", mock.Anything, mock.Anything, mock.Anything).
			Return(&dexapi.UpdatePasswordResp{}, nil)

		resp, err = r.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      updatedUser.Name,
				Namespace: updatedUser.Namespace,
			},
		})
		require.NoError(t, err)
		assert.Zero(t, resp)

		require.Len(t, eventRecorder.Events, 1)
		event = <-eventRecorder.Events

		assert.Equal(t, "Normal Ready Successfully created or updated", event)

		updatedUser = user.DeepCopy()
		err = subResourceClient.Get(ctx, user, updatedUser)
		require.NoError(t, err)

		assert.Equal(t, dexv1alpha1.DexUserPhaseReady, updatedUser.Status.Phase)
	})

	t.Run("Delete", func(t *testing.T) {
		deletingUser := user.DeepCopy()
		deletingUser.DeletionTimestamp = &metav1.Time{Time: metav1.Now().Add(-1 * time.Second)}
		deletingUser.Finalizers = []string{controller.FinalizerName}

		eventRecorder := record.NewFakeRecorder(2)
		r.Recorder = eventRecorder

		subResourceClient.Reset()

		r.Client = fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(deletingUser, idp).
			WithStatusSubresource(deletingUser).
			WithInterceptorFuncs(interceptorFuncs).
			Build()

		var m mock.Mock
		r.DexClientBuilder = dex.NewFakeClientBuilder(&m)

		m.On("DeletePassword", mock.Anything, mock.Anything, mock.Anything).
			Return(&dexapi.DeletePasswordResp{}, nil)

		resp, err := r.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      idp.Name,
				Namespace: idp.Namespace,
			},
		})
		require.NoError(t, err)
		assert.Zero(t, resp)

		assert.Len(t, eventRecorder.Events, 0)

		m.AssertCalled(t, "DeletePassword", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("References Not Resolvable", func(t *testing.T) {
		eventRecorder := record.NewFakeRecorder(2)
		r.Recorder = eventRecorder

		subResourceClient.Reset()

		r.Client = fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(user). // Note missing IDP
			WithStatusSubresource(user).
			WithInterceptorFuncs(interceptorFuncs).
			Build()

		resp, err := r.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      user.Name,
				Namespace: user.Namespace,
			},
		})
		require.NoError(t, err)
		assert.NotZero(t, resp.RequeueAfter)

		require.Len(t, eventRecorder.Events, 1)
		event := <-eventRecorder.Events
		assert.Equal(t, "Warning NotReady Not all references are resolvable", event)

		updatedUser := user.DeepCopy()
		err = subResourceClient.Get(ctx, user, updatedUser)
		require.NoError(t, err)

		assert.Equal(t, dexv1alpha1.DexUserPhasePending, updatedUser.Status.Phase)
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
			WithObjects(user, idp).
			WithStatusSubresource(user).
			WithInterceptorFuncs(failOnSecrets).
			Build()

		_, err := r.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      user.Name,
				Namespace: user.Namespace,
			},
		})
		require.Error(t, err)

		require.Len(t, eventRecorder.Events, 1)
		event := <-eventRecorder.Events
		assert.Equal(t, "Warning Failed Failed to get user password secret", event)

		updatedUser := user.DeepCopy()
		err = subResourceClient.Get(ctx, user, updatedUser)
		require.NoError(t, err)

		assert.Equal(t, dexv1alpha1.DexUserPhaseFailed, updatedUser.Status.Phase)
	})
}
