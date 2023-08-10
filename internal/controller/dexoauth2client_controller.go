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
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/dexidp/dex/api/v2"
	"github.com/google/uuid"
	dexv1alpha1 "github.com/gpu-ninja/dex-operator/api/v1alpha1"
	"github.com/gpu-ninja/dex-operator/internal/dex"
	"github.com/gpu-ninja/operator-utils/retryable"
	"github.com/gpu-ninja/operator-utils/zaplogr"
)

//+kubebuilder:rbac:groups=dex.gpu-ninja.com,resources=dexoauth2clients,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=dex.gpu-ninja.com,resources=dexoauth2clients/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=dex.gpu-ninja.com,resources=dexoauth2clients/finalizers,verbs=update

// DexOAuth2ClientReconciler reconciles a DexOAuth2Client object
type DexOAuth2ClientReconciler struct {
	client.Client
	Scheme           *runtime.Scheme
	EventRecorder    record.EventRecorder
	DexClientBuilder dex.ClientBuilder
}

func (r *DexOAuth2ClientReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := zaplogr.FromContext(ctx)

	logger.Info("Reconciling Dex OAuth2 Client")

	var oauth2Client dexv1alpha1.DexOAuth2Client
	err := r.Get(ctx, req.NamespacedName, &oauth2Client)
	if err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, err
	}

	if !controllerutil.ContainsFinalizer(&oauth2Client, finalizerName) {
		logger.Info("Adding Finalizer")

		_, err := controllerutil.CreateOrPatch(ctx, r.Client, &oauth2Client, func() error {
			controllerutil.AddFinalizer(&oauth2Client, finalizerName)

			return nil
		})
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to add finalizer: %w", err)
		}
	}

	// Make sure all references are resolvable.
	if err := oauth2Client.ResolveReferences(ctx, r.Client, r.Scheme); err != nil {
		if retryable.IsRetryable(err) {
			if !oauth2Client.GetDeletionTimestamp().IsZero() {
				// Parent has probably been removed by a cascading delete.
				// So there is probably no point in retrying.

				_, err := controllerutil.CreateOrPatch(ctx, r.Client, &oauth2Client, func() error {
					controllerutil.RemoveFinalizer(&oauth2Client, finalizerName)

					return nil
				})
				if err != nil {
					return ctrl.Result{}, fmt.Errorf("failed to remove finalizer: %w", err)
				}

				return ctrl.Result{}, nil
			}

			logger.Info("Not all references are resolvable, requeuing")

			r.EventRecorder.Event(&oauth2Client, corev1.EventTypeWarning,
				"NotReady", "Not all references are resolvable")

			if err := r.markPending(ctx, &oauth2Client); err != nil {
				return ctrl.Result{}, err
			}

			return ctrl.Result{RequeueAfter: reconcileRetryInterval}, nil
		}

		logger.Error("Failed to resolve references", zap.Error(err))

		r.EventRecorder.Eventf(&oauth2Client, corev1.EventTypeWarning,
			"Failed", "Failed to resolve references: %s", err)

		r.markFailed(ctx, &oauth2Client, fmt.Errorf("failed to resolve references: %w", err))

		return ctrl.Result{}, nil
	}

	idpObj, err := oauth2Client.Spec.IdentityProviderRef.Resolve(ctx, r.Client, r.Scheme, &oauth2Client)
	if err != nil {
		logger.Error("Failed to resolve Dex Identity Provider reference", zap.Error(err))

		r.EventRecorder.Eventf(&oauth2Client, corev1.EventTypeWarning,
			"Failed", "Failed to resolve dex identity provider reference: %s", err)

		r.markFailed(ctx, &oauth2Client,
			fmt.Errorf("failed to resolve dex identity provider reference: %w", err))

		return ctrl.Result{}, nil
	}
	idp := idpObj.(*dexv1alpha1.DexIdentityProvider)

	// Is the dex identity provider ready?
	if idp.Status.Phase != dexv1alpha1.DexIdentityProviderPhaseReady {
		logger.Warn("Referenced Dex Identity Provider not ready",
			zap.String("namespace", idp.Namespace), zap.String("name", idp.Name))

		r.EventRecorder.Eventf(&oauth2Client, corev1.EventTypeWarning,
			"NotReady", "Dex identity provider %s in namespace %s not ready",
			idp.Name, idp.Namespace)

		if err := r.markPending(ctx, &oauth2Client); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{RequeueAfter: reconcileRetryInterval}, nil
	}

	clientSecretNamespaceName := types.NamespacedName{
		Namespace: oauth2Client.Namespace,
		Name:      oauth2Client.Spec.SecretName,
	}
	clientSecret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      clientSecretNamespaceName.Name,
			Namespace: clientSecretNamespaceName.Namespace,
		},
	}

	var creating bool
	if err := r.Client.Get(ctx, clientSecretNamespaceName, &clientSecret); err != nil {
		if errors.IsNotFound(err) {
			creating = true
		} else {
			logger.Error("Failed to get Dex OAuth2 Client secret", zap.Error(err))

			r.EventRecorder.Event(&oauth2Client, corev1.EventTypeWarning,
				"Failed", "Failed to get dex oauth2 client secret")

			r.markFailed(ctx, &oauth2Client, fmt.Errorf("failed to get dex oauth2 client secret: %w", err))

			return ctrl.Result{}, nil
		}
	}

	if !oauth2Client.ObjectMeta.DeletionTimestamp.IsZero() {
		logger.Info("Deleting Dex OAuth2 Client")

		if !creating {
			dexAPIClient, err := r.DexClientBuilder.
				WithIdentityProvider(idp).
				Build(ctx)
			if err != nil {
				// Don't block deletion.
				logger.Error("Failed to build Dex API client, skipping deletion", zap.Error(err))
			} else {
				oauth2ClientID := clientSecret.Data["client_id"]
				_, err := dexAPIClient.DeleteClient(ctx, &api.DeleteClientReq{
					Id: string(oauth2ClientID),
				})
				if err != nil {
					// Don't block deletion.
					logger.Error("Failed to delete Dex OAuth2 Client, skipping deletion", zap.Error(err))
				}
			}
		}

		if controllerutil.ContainsFinalizer(&oauth2Client, finalizerName) {
			logger.Info("Removing Finalizer")

			_, err := controllerutil.CreateOrPatch(ctx, r.Client, &oauth2Client, func() error {
				controllerutil.RemoveFinalizer(&oauth2Client, finalizerName)

				return nil
			})
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to remove finalizer: %w", err)
			}
		}

		return ctrl.Result{}, nil
	}

	if oauth2Client.Status.Phase == dexv1alpha1.DexOAuth2ClientPhaseFailed {
		logger.Info("Dex OAuth2 Client is in failed state, ignoring")

		return ctrl.Result{}, nil
	}

	logger.Info("Creating or updating Dex OAuth2 Client")

	dexAPIClient, err := r.DexClientBuilder.
		WithIdentityProvider(idp).
		Build(ctx)
	if err != nil {
		logger.Error("Failed to build Dex API client", zap.Error(err))

		r.EventRecorder.Eventf(&oauth2Client, corev1.EventTypeWarning,
			"Failed", "Failed to build Dex API client: %s", err)

		if err := r.markPending(ctx, &oauth2Client); err != nil {
			return ctrl.Result{}, err
		}

		// Could very well be a temporary error, so retry.
		return ctrl.Result{RequeueAfter: reconcileRetryInterval}, nil
	}

	if creating {
		logger.Info("Creating new Dex OAuth2 Client secret")

		oauth2ClientID := uuid.New().String()
		oauth2ClientSecret := generateRandomString(16)

		_, err := controllerutil.CreateOrPatch(ctx, r.Client, &clientSecret, func() error {
			if err := controllerutil.SetControllerReference(&oauth2Client, &clientSecret, r.Scheme); err != nil {
				return fmt.Errorf("failed to set controller reference: %w", err)
			}

			clientSecret.StringData = map[string]string{
				"client_id":     oauth2ClientID,
				"client_secret": oauth2ClientSecret,
			}

			return nil
		})
		if err != nil {
			logger.Error("Failed to create Dex OAuth2 Client secret", zap.Error(err))

			r.EventRecorder.Event(&oauth2Client, corev1.EventTypeWarning,
				"Failed", "Failed to create dex oauth2 client secret")

			r.markFailed(ctx, &oauth2Client, fmt.Errorf("failed to create dex oauth2 client secret: %w", err))

			return ctrl.Result{}, nil
		}
	}

	// TODO: use GetClient() when it is released.

	updateResp, err := dexAPIClient.UpdateClient(ctx, &api.UpdateClientReq{
		Id:           string(clientSecret.Data["client_id"]),
		RedirectUris: oauth2Client.Spec.RedirectURIs,
		TrustedPeers: oauth2Client.Spec.TrustedPeers,
		Name:         oauth2Client.Spec.Name,
		LogoUrl:      oauth2Client.Spec.LogoURL,
	})
	if err != nil {
		logger.Error("Failed to update Dex OAuth2 Client", zap.Error(err))

		r.EventRecorder.Event(&oauth2Client, corev1.EventTypeWarning,
			"Failed", "Failed to update dex oauth2 client")

		if err := r.markPending(ctx, &oauth2Client); err != nil {
			return ctrl.Result{}, err
		}

		// Could very well be transient, so retry.
		return ctrl.Result{RequeueAfter: reconcileRetryInterval}, nil
	}

	if updateResp.NotFound {
		logger.Info("Dex OAuth2 Client not found, creating")

		_, err = dexAPIClient.CreateClient(ctx, &api.CreateClientReq{
			Client: &api.Client{
				Id:           string(clientSecret.Data["client_id"]),
				Secret:       string(clientSecret.Data["client_secret"]),
				RedirectUris: oauth2Client.Spec.RedirectURIs,
				TrustedPeers: oauth2Client.Spec.TrustedPeers,
				Public:       oauth2Client.Spec.Public,
				Name:         oauth2Client.Spec.Name,
				LogoUrl:      oauth2Client.Spec.LogoURL,
			},
		})
		if err != nil {
			logger.Error("Failed to create Dex OAuth2 Client", zap.Error(err))

			r.EventRecorder.Event(&oauth2Client, corev1.EventTypeWarning,
				"Failed", "Failed to create dex oauth2 client")

			r.markFailed(ctx, &oauth2Client,
				fmt.Errorf("failed to create dex oauth2 client: %w", err))

			return ctrl.Result{}, nil
		}
	}

	if oauth2Client.Status.Phase != dexv1alpha1.DexOAuth2ClientPhaseReady {
		r.EventRecorder.Event(&oauth2Client, corev1.EventTypeNormal,
			"Created", "Successfully created")

		if err := r.markReady(ctx, &oauth2Client); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func (r *DexOAuth2ClientReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&dexv1alpha1.DexOAuth2Client{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}

func (r *DexOAuth2ClientReconciler) markPending(ctx context.Context, oauth2Client *dexv1alpha1.DexOAuth2Client) error {
	_, err := controllerutil.CreateOrPatch(ctx, r.Client, oauth2Client, func() error {
		oauth2Client.Status.ObservedGeneration = oauth2Client.Generation
		oauth2Client.Status.Phase = dexv1alpha1.DexOAuth2ClientPhasePending

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to mark as pending: %w", err)
	}

	return nil
}

func (r *DexOAuth2ClientReconciler) markReady(ctx context.Context, oauth2Client *dexv1alpha1.DexOAuth2Client) error {
	_, err := controllerutil.CreateOrPatch(ctx, r.Client, oauth2Client, func() error {
		oauth2Client.Status.ObservedGeneration = oauth2Client.Generation
		oauth2Client.Status.Phase = dexv1alpha1.DexOAuth2ClientPhaseReady

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to mark as ready: %w", err)
	}

	return nil
}

func (r *DexOAuth2ClientReconciler) markFailed(ctx context.Context, oauth2Client *dexv1alpha1.DexOAuth2Client, err error) {
	logger := zaplogr.FromContext(ctx)

	_, updateErr := controllerutil.CreateOrPatch(ctx, r.Client, oauth2Client, func() error {
		oauth2Client.Status.ObservedGeneration = oauth2Client.Generation
		oauth2Client.Status.Phase = dexv1alpha1.DexOAuth2ClientPhaseFailed
		oauth2Client.Status.Reason = err.Error()

		return nil
	})
	if updateErr != nil {
		logger.Error("Failed to mark as failed", zap.Error(updateErr))
	}
}

func generateRandomString(length int) string {
	buffer := make([]byte, length)
	_, _ = rand.Read(buffer)
	return base64.RawStdEncoding.EncodeToString(buffer)
}
