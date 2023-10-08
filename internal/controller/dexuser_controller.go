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

package controller

import (
	"context"
	"fmt"

	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	dexapi "github.com/dexidp/dex/api/v2"
	"github.com/google/uuid"
	dexv1alpha1 "github.com/gpu-ninja/dex-operator/api/v1alpha1"
	"github.com/gpu-ninja/dex-operator/internal/dex"
	"github.com/gpu-ninja/operator-utils/password"
	"github.com/gpu-ninja/operator-utils/updater"
	"github.com/gpu-ninja/operator-utils/zaplogr"
)

// +kubebuilder:rbac:groups=dex.gpu-ninja.com,resources=dexusers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=dex.gpu-ninja.com,resources=dexusers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=dex.gpu-ninja.com,resources=dexusers/finalizers,verbs=update

// DexUserReconciler reconciles a DexUser object
type DexUserReconciler struct {
	client.Client
	Scheme           *runtime.Scheme
	Recorder         record.EventRecorder
	DexClientBuilder dex.ClientBuilder
}

func (r *DexUserReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := zaplogr.FromContext(ctx)

	logger.Info("Reconciling")

	var user dexv1alpha1.DexUser
	err := r.Get(ctx, req.NamespacedName, &user)
	if err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, err
	}

	if !controllerutil.ContainsFinalizer(&user, FinalizerName) {
		logger.Info("Adding Finalizer")

		_, err := controllerutil.CreateOrPatch(ctx, r.Client, &user, func() error {
			controllerutil.AddFinalizer(&user, FinalizerName)

			return nil
		})
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to add finalizer: %w", err)
		}
	}

	ok, err := user.ResolveReferences(ctx, r.Client, r.Scheme)
	if !ok && err == nil {
		if !user.GetDeletionTimestamp().IsZero() {
			// Parent has probably been removed by a cascading delete.
			// So there is probably no point in retrying.

			_, err := controllerutil.CreateOrPatch(ctx, r.Client, &user, func() error {
				controllerutil.RemoveFinalizer(&user, FinalizerName)

				return nil
			})
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to remove finalizer: %w", err)
			}

			return ctrl.Result{}, nil
		}

		logger.Info("Not all references are resolvable, requeuing")

		r.Recorder.Event(&user, corev1.EventTypeWarning,
			"NotReady", "Not all references are resolvable")

		if err := r.markPending(ctx, &user); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{RequeueAfter: reconcileRetryInterval}, nil
	} else if err != nil {
		r.Recorder.Eventf(&user, corev1.EventTypeWarning,
			"Failed", "Failed to resolve references: %s", err)

		r.markFailed(ctx, &user,
			fmt.Errorf("failed to resolve references: %w", err))

		return ctrl.Result{}, fmt.Errorf("failed to resolve references: %w", err)
	}

	idpObj, ok, err := user.Spec.IdentityProviderRef.Resolve(ctx, r.Client, r.Scheme, &user)
	if err != nil {
		logger.Error("Failed to resolve Identity Provider reference", zap.Error(err))

		r.Recorder.Eventf(&user, corev1.EventTypeWarning,
			"Failed", "Failed to resolve identity provider reference: %s", err)

		r.markFailed(ctx, &user,
			fmt.Errorf("failed to resolve identity provider reference: %w", err))

		return ctrl.Result{}, nil
	}
	if !ok {
		return ctrl.Result{}, fmt.Errorf("failed to resolve identity provider reference")
	}
	idp := idpObj.(*dexv1alpha1.DexIdentityProvider)

	// Is the dex identity provider ready?
	if idp.Status.Phase != dexv1alpha1.DexIdentityProviderPhaseReady {
		logger.Info("Referenced Identity Provider not ready",
			zap.String("namespace", idp.Namespace), zap.String("name", idp.Name))

		r.Recorder.Event(&user, corev1.EventTypeWarning,
			"NotReady", "Referenced identity provider is not ready")

		if err := r.markPending(ctx, &user); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{RequeueAfter: reconcileRetryInterval}, nil
	}

	if !user.GetDeletionTimestamp().IsZero() {
		logger.Info("Deleting")

		dexAPIClient, err := r.DexClientBuilder.
			WithIdentityProvider(idp).
			Build(ctx)
		if err != nil {
			// Don't block deletion.
			logger.Error("Failed to build api client, skipping deletion", zap.Error(err))
		} else {
			_, err := dexAPIClient.DeletePassword(ctx, &dexapi.DeletePasswordReq{
				Email: user.Spec.Email,
			})
			if err != nil {
				// Don't block deletion.
				logger.Error("Failed to delete, skipping deletion", zap.Error(err))
			}
		}

		if controllerutil.ContainsFinalizer(&user, FinalizerName) {
			logger.Info("Removing Finalizer")

			_, err := controllerutil.CreateOrPatch(ctx, r.Client, &user, func() error {
				controllerutil.RemoveFinalizer(&user, FinalizerName)

				return nil
			})
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to remove finalizer: %w", err)
			}
		}

		return ctrl.Result{}, nil
	}

	logger.Info("Creating or updating")

	if err := r.setOwner(ctx, &user, idp); err != nil {
		logger.Error("Failed to set owner reference", zap.Error(err))

		r.Recorder.Eventf(&user, corev1.EventTypeWarning,
			"Failed", "Failed to set owner reference: %s", err)

		r.markFailed(ctx, &user,
			fmt.Errorf("failed to set owner reference: %w", err))

		return ctrl.Result{}, nil
	}

	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      user.Spec.SecretName,
			Namespace: user.Namespace,
		},
		Data: make(map[string][]byte),
	}

	if err := r.Client.Get(ctx, client.ObjectKeyFromObject(&secret), &secret); err != nil {
		if !errors.IsNotFound(err) {
			logger.Error("Failed to get user password secret", zap.Error(err))

			r.Recorder.Event(&user, corev1.EventTypeWarning,
				"Failed", "Failed to get user password secret")

			r.markFailed(ctx, &user,
				fmt.Errorf("failed to get user password secret: %w", err))

			return ctrl.Result{}, fmt.Errorf("failed to get user password secret: %w", err)
		}
	}

	dexAPIClient, err := r.DexClientBuilder.
		WithIdentityProvider(idp).
		Build(ctx)
	if err != nil {
		logger.Error("Failed to build api client", zap.Error(err))

		r.Recorder.Eventf(&user, corev1.EventTypeWarning,
			"Failed", "Failed to build api client: %s", err)

		if err := r.markPending(ctx, &user); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{}, fmt.Errorf("failed to build api client: %w", err)
	}

	if pw, ok := secret.Data["password"]; ok {
		hash, err := bcrypt.GenerateFromPassword(pw, bcrypt.DefaultCost)
		if err != nil {
			logger.Error("Failed to hash password", zap.Error(err))

			r.Recorder.Event(&user, corev1.EventTypeWarning,
				"Failed", "Failed to hash password")

			r.markFailed(ctx, &user,
				fmt.Errorf("failed to hash password: %w", err))

			return ctrl.Result{}, fmt.Errorf("failed to hash password: %w", err)
		}

		verifyResp, err := dexAPIClient.VerifyPassword(ctx, &dexapi.VerifyPasswordReq{
			Email:    user.Spec.Email,
			Password: string(pw),
		})
		if err != nil {
			logger.Error("Failed to verify existing password via Dex API", zap.Error(err))

			r.Recorder.Event(&user, corev1.EventTypeWarning,
				"Failed", "Failed to verify existing password via dex api")

			if err := r.markPending(ctx, &user); err != nil {
				return ctrl.Result{}, err
			}

			return ctrl.Result{}, fmt.Errorf("failed to verify existing password via dex api: %w", err)
		}

		if verifyResp.NotFound {
			logger.Info("Creating password from existing secret")

			_, err := dexAPIClient.CreatePassword(ctx, &dexapi.CreatePasswordReq{
				Password: &dexapi.Password{
					Email:  user.Spec.Email,
					Hash:   hash,
					UserId: uuid.New().String(),
				},
			})
			if err != nil {
				logger.Error("Failed to create password via Dex API", zap.Error(err))

				r.Recorder.Event(&user, corev1.EventTypeWarning,
					"Failed", "Failed to create password via dex api")

				r.markFailed(ctx, &user,
					fmt.Errorf("failed to create password via dex api: %w", err))

				return ctrl.Result{}, fmt.Errorf("failed to create password via dex api: %w", err)
			}

		} else if !verifyResp.Verified {
			logger.Info("Password has changed, updating")

			if err := r.markPending(ctx, &user); err != nil {
				return ctrl.Result{}, err
			}

			_, err := dexAPIClient.UpdatePassword(ctx, &dexapi.UpdatePasswordReq{
				Email:   user.Spec.Email,
				NewHash: hash,
			})
			if err != nil {
				logger.Error("Failed to update password via Dex API", zap.Error(err))

				r.Recorder.Event(&user, corev1.EventTypeWarning,
					"Failed", "Failed to update password via dex api")

				r.markFailed(ctx, &user,
					fmt.Errorf("failed to update password via dex api: %w", err))

				return ctrl.Result{}, fmt.Errorf("failed to update password via dex api: %w", err)
			}
		}
	} else {
		logger.Info("Creating password")

		pw, err := password.Generate(16)
		if err != nil {
			logger.Error("Failed to generate password", zap.Error(err))

			r.Recorder.Event(&user, corev1.EventTypeWarning,
				"Failed", "Failed to generate password")

			r.markFailed(ctx, &user,
				fmt.Errorf("failed to generate password: %w", err))

			return ctrl.Result{}, fmt.Errorf("failed to generate password: %w", err)
		}

		logger.Info("Storing password in secret")

		secret, err := r.secretTemplate(&user, pw)
		if err != nil {
			r.Recorder.Eventf(&user, corev1.EventTypeWarning,
				"Failed", "Failed to generate user password secret template: %s", err)

			r.markFailed(ctx, &user,
				fmt.Errorf("failed to generate user password secret template: %w", err))

			return ctrl.Result{}, fmt.Errorf("failed to generate user password secret template: %w", err)
		}

		if _, err := updater.CreateOrUpdateFromTemplate(ctx, r.Client, secret); err != nil {
			r.Recorder.Eventf(&user, corev1.EventTypeWarning,
				"Failed", "Failed to reconcile user password secret: %s", err)

			r.markFailed(ctx, &user,
				fmt.Errorf("failed to reconcile user password secret: %w", err))

			return ctrl.Result{}, fmt.Errorf("failed to reconcile user password secret: %w", err)
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
		if err != nil {
			logger.Error("Failed to hash password", zap.Error(err))

			r.Recorder.Event(&user, corev1.EventTypeWarning,
				"Failed", "Failed to hash password")

			r.markFailed(ctx, &user,
				fmt.Errorf("failed to hash password: %w", err))

			return ctrl.Result{}, fmt.Errorf("failed to hash password: %w", err)
		}

		_, err = dexAPIClient.CreatePassword(ctx, &dexapi.CreatePasswordReq{
			Password: &dexapi.Password{
				Email:  user.Spec.Email,
				Hash:   hash,
				UserId: uuid.New().String(),
			},
		})
		if err != nil {
			logger.Error("Failed to create password via Dex API", zap.Error(err))

			r.Recorder.Event(&user, corev1.EventTypeWarning,
				"Failed", "Failed to create password via dex api")

			r.markFailed(ctx, &user,
				fmt.Errorf("failed to create password via dex api: %w", err))

			return ctrl.Result{}, fmt.Errorf("failed to create password via dex api: %w", err)
		}
	}

	if user.Status.Phase != dexv1alpha1.DexUserPhaseReady {
		r.Recorder.Event(&user, corev1.EventTypeNormal,
			"Ready", "Successfully created or updated")

		if err := r.markReady(ctx, &user); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func (r *DexUserReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&dexv1alpha1.DexUser{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}

func (r *DexUserReconciler) markPending(ctx context.Context, user *dexv1alpha1.DexUser) error {
	err := updater.UpdateStatus(ctx, r.Client, client.ObjectKeyFromObject(user), user, func() error {
		user.Status.ObservedGeneration = user.ObjectMeta.Generation
		user.Status.Phase = dexv1alpha1.DexUserPhasePending

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to mark as pending: %w", err)
	}

	return nil
}

func (r *DexUserReconciler) markReady(ctx context.Context, user *dexv1alpha1.DexUser) error {
	err := updater.UpdateStatus(ctx, r.Client, client.ObjectKeyFromObject(user), user, func() error {
		user.Status.ObservedGeneration = user.Generation
		user.Status.Phase = dexv1alpha1.DexUserPhaseReady

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to mark as ready: %w", err)
	}

	return nil
}

func (r *DexUserReconciler) markFailed(ctx context.Context, user *dexv1alpha1.DexUser, err error) {
	logger := zaplogr.FromContext(ctx)

	updateErr := updater.UpdateStatus(ctx, r.Client, client.ObjectKeyFromObject(user), user, func() error {
		user.Status.ObservedGeneration = user.Generation
		user.Status.Phase = dexv1alpha1.DexUserPhaseFailed
		user.Status.Reason = err.Error()

		return nil
	})
	if updateErr != nil {
		logger.Error("Failed to mark as failed", zap.Error(updateErr))
	}
}

func (r *DexUserReconciler) setOwner(ctx context.Context, user *dexv1alpha1.DexUser, idp *dexv1alpha1.DexIdentityProvider) error {
	_, err := controllerutil.CreateOrPatch(ctx, r.Client, user, func() error {
		return controllerutil.SetControllerReference(idp, user, r.Scheme)
	})
	if err != nil {
		return err
	}

	return nil
}

func (r *DexUserReconciler) secretTemplate(user *dexv1alpha1.DexUser, pw string) (*corev1.Secret, error) {
	secret := corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: corev1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      user.Spec.SecretName,
			Namespace: user.Namespace,
			Labels:    make(map[string]string),
		},
		Data: map[string][]byte{
			"password": []byte(pw),
		},
	}

	if err := controllerutil.SetControllerReference(user, &secret, r.Scheme); err != nil {
		return nil, fmt.Errorf("failed to set controller reference: %w", err)
	}

	for k, v := range user.ObjectMeta.Labels {
		secret.ObjectMeta.Labels[k] = v
	}

	secret.ObjectMeta.Labels["app.kubernetes.io/name"] = "dexuser"
	secret.ObjectMeta.Labels["app.kubernetes.io/instance"] = user.Name
	secret.ObjectMeta.Labels["app.kubernetes.io/managed-by"] = "dex-operator"

	return &secret, nil
}
