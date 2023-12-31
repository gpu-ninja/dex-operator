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
	"github.com/gpu-ninja/dex-operator/api"
	dexv1alpha1 "github.com/gpu-ninja/dex-operator/api/v1alpha1"
	"github.com/gpu-ninja/dex-operator/internal/dex"
	"github.com/gpu-ninja/operator-utils/password"
	"github.com/gpu-ninja/operator-utils/updater"
	"github.com/gpu-ninja/operator-utils/zaplogr"
)

// +kubebuilder:rbac:groups=dex.gpu-ninja.com,resources=dexoauth2clients,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=dex.gpu-ninja.com,resources=dexoauth2clients/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=dex.gpu-ninja.com,resources=dexoauth2clients/finalizers,verbs=update

// DexOAuth2ClientReconciler reconciles a DexOAuth2Client object
type DexOAuth2ClientReconciler struct {
	client.Client
	Scheme           *runtime.Scheme
	Recorder         record.EventRecorder
	DexClientBuilder dex.ClientBuilder
}

func (r *DexOAuth2ClientReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := zaplogr.FromContext(ctx)

	logger.Info("Reconciling")

	var oauth2Client dexv1alpha1.DexOAuth2Client
	err := r.Get(ctx, req.NamespacedName, &oauth2Client)
	if err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, err
	}

	if !controllerutil.ContainsFinalizer(&oauth2Client, FinalizerName) {
		logger.Info("Adding Finalizer")

		_, err := controllerutil.CreateOrPatch(ctx, r.Client, &oauth2Client, func() error {
			controllerutil.AddFinalizer(&oauth2Client, FinalizerName)

			return nil
		})
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to add finalizer: %w", err)
		}
	}

	ok, err := oauth2Client.ResolveReferences(ctx, r.Client, r.Scheme)
	if !ok && err == nil {
		if !oauth2Client.GetDeletionTimestamp().IsZero() {
			// Parent has probably been removed by a cascading delete.
			// So there is probably no point in retrying.

			_, err := controllerutil.CreateOrPatch(ctx, r.Client, &oauth2Client, func() error {
				controllerutil.RemoveFinalizer(&oauth2Client, FinalizerName)

				return nil
			})
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to remove finalizer: %w", err)
			}

			return ctrl.Result{}, nil
		}

		logger.Info("Not all references are resolvable, requeuing")

		r.Recorder.Event(&oauth2Client, corev1.EventTypeWarning,
			"NotReady", "Not all references are resolvable")

		if err := r.markPending(ctx, &oauth2Client); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{RequeueAfter: reconcileRetryInterval}, nil
	} else if err != nil {
		r.Recorder.Eventf(&oauth2Client, corev1.EventTypeWarning,
			"Failed", "Failed to resolve references: %s", err)

		r.markFailed(ctx, &oauth2Client,
			fmt.Errorf("failed to resolve references: %w", err))

		return ctrl.Result{}, fmt.Errorf("failed to resolve references: %w", err)
	}

	idpObj, ok, err := oauth2Client.Spec.IdentityProviderRef.Resolve(ctx, r.Client, r.Scheme, &oauth2Client)
	if err != nil || !ok {
		return ctrl.Result{}, fmt.Errorf("failed to resolve identity provider reference")
	}
	idp := idpObj.(*dexv1alpha1.DexIdentityProvider)

	// Is the dex identity provider ready?
	if idp.Status.Phase != dexv1alpha1.DexIdentityProviderPhaseReady {
		logger.Info("Referenced Identity Provider not ready",
			zap.String("namespace", idp.Namespace), zap.String("name", idp.Name))

		r.Recorder.Event(&oauth2Client, corev1.EventTypeWarning,
			"NotReady", "Referenced identity provider is not ready")

		if err := r.markPending(ctx, &oauth2Client); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{RequeueAfter: reconcileRetryInterval}, nil
	}

	clientSecret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      oauth2Client.Spec.SecretName,
			Namespace: oauth2Client.Namespace,
		},
	}

	var creating bool
	if err := r.Client.Get(ctx, client.ObjectKeyFromObject(&clientSecret), &clientSecret); err != nil {
		if errors.IsNotFound(err) {
			creating = true
		} else {
			logger.Error("Failed to get client secret", zap.Error(err))

			r.Recorder.Event(&oauth2Client, corev1.EventTypeWarning,
				"Failed", "Failed to get client secret")

			r.markFailed(ctx, &oauth2Client,
				fmt.Errorf("failed to get client secret: %w", err))

			return ctrl.Result{}, fmt.Errorf("failed to get client secret: %w", err)
		}
	}

	if !oauth2Client.GetDeletionTimestamp().IsZero() {
		logger.Info("Deleting")

		if !creating {
			dexAPIClient, err := r.DexClientBuilder.
				WithIdentityProvider(idp).
				Build(ctx)
			if err != nil {
				// Don't block deletion.
				logger.Error("Failed to build api client, skipping deletion", zap.Error(err))
			} else {
				oauth2ClientID := clientSecret.Data["id"]
				_, err := dexAPIClient.DeleteClient(ctx, &dexapi.DeleteClientReq{
					Id: string(oauth2ClientID),
				})
				if err != nil {
					// Don't block deletion.
					logger.Error("Failed to delete, skipping deletion", zap.Error(err))
				}
			}
		}

		if controllerutil.ContainsFinalizer(&oauth2Client, FinalizerName) {
			logger.Info("Removing Finalizer")

			_, err := controllerutil.CreateOrPatch(ctx, r.Client, &oauth2Client, func() error {
				controllerutil.RemoveFinalizer(&oauth2Client, FinalizerName)

				return nil
			})
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to remove finalizer: %w", err)
			}
		}

		return ctrl.Result{}, nil
	}

	logger.Info("Creating or updating")

	if err := r.setOwner(ctx, &oauth2Client, idp); err != nil {
		logger.Error("Failed to set owner reference", zap.Error(err))

		r.Recorder.Eventf(&oauth2Client, corev1.EventTypeWarning,
			"Failed", "Failed to set owner reference: %s", err)

		r.markFailed(ctx, &oauth2Client,
			fmt.Errorf("failed to set owner reference: %w", err))

		return ctrl.Result{}, fmt.Errorf("failed to set owner reference: %w", err)
	}

	dexAPIClient, err := r.DexClientBuilder.
		WithIdentityProvider(idp).
		Build(ctx)
	if err != nil {
		logger.Error("Failed to build api client", zap.Error(err))

		r.Recorder.Eventf(&oauth2Client, corev1.EventTypeWarning,
			"Failed", "Failed to build api client: %s", err)

		if err := r.markPending(ctx, &oauth2Client); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{}, fmt.Errorf("failed to build api client: %w", err)
	}

	var oauth2ClientID, oauth2ClientSecret string
	if !creating {
		oauth2ClientID = string(clientSecret.Data["id"])
		oauth2ClientSecret = string(clientSecret.Data["secret"])
	} else {
		oauth2ClientID = uuid.New().String()
		oauth2ClientSecret, err = password.Generate(32)
		if err != nil {
			logger.Error("Failed to generate client secret", zap.Error(err))

			r.Recorder.Event(&oauth2Client, corev1.EventTypeWarning,
				"Failed", "Failed to generate client secret")

			r.markFailed(ctx, &oauth2Client,
				fmt.Errorf("failed to generate client secret: %w", err))

			return ctrl.Result{}, fmt.Errorf("failed to generate client secret: %w", err)
		}
	}

	// TODO: use GetClient() when it is released (so that we can detect updates).

	updateResp, err := dexAPIClient.UpdateClient(ctx, &dexapi.UpdateClientReq{
		Id:           oauth2ClientID,
		RedirectUris: oauth2Client.Spec.RedirectURIs,
		TrustedPeers: oauth2Client.Spec.TrustedPeers,
		Name:         oauth2Client.Spec.Name,
		LogoUrl:      oauth2Client.Spec.LogoURL,
	})
	if err != nil {
		logger.Error("Failed to update client via Dex API", zap.Error(err))

		r.Recorder.Event(&oauth2Client, corev1.EventTypeWarning,
			"Failed", "Failed to update client via dex api")

		if err := r.markPending(ctx, &oauth2Client); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{}, fmt.Errorf("failed to update client via dex api: %w", err)
	}

	if updateResp.NotFound {
		logger.Info("Client not found, creating")

		_, err = dexAPIClient.CreateClient(ctx, &dexapi.CreateClientReq{
			Client: &dexapi.Client{
				Id:           oauth2ClientID,
				Secret:       oauth2ClientSecret,
				RedirectUris: oauth2Client.Spec.RedirectURIs,
				TrustedPeers: oauth2Client.Spec.TrustedPeers,
				Public:       oauth2Client.Spec.Public,
				Name:         oauth2Client.Spec.Name,
				LogoUrl:      oauth2Client.Spec.LogoURL,
			},
		})
		if err != nil {
			logger.Error("Failed to create client via Dex API", zap.Error(err))

			r.Recorder.Event(&oauth2Client, corev1.EventTypeWarning,
				"Failed", "Failed to create client via dex api")

			r.markFailed(ctx, &oauth2Client,
				fmt.Errorf("failed to create client via dex api: %w", err))

			return ctrl.Result{}, fmt.Errorf("failed to create client via dex api: %w", err)
		}
	}

	if creating {
		logger.Info("Saving client secret")

		clientSecret, err := r.clientSecretTemplate(&oauth2Client, oauth2ClientID, oauth2ClientSecret)
		if err != nil {
			r.Recorder.Eventf(&oauth2Client, corev1.EventTypeWarning,
				"Failed", "Failed to generate client secret template: %s", err)

			r.markFailed(ctx, &oauth2Client,
				fmt.Errorf("failed to generate client secret template: %w", err))

			return ctrl.Result{}, fmt.Errorf("failed to generate client secret template: %w", err)
		}

		if _, err := updater.CreateOrUpdateFromTemplate(ctx, r.Client, clientSecret); err != nil {
			r.Recorder.Eventf(&oauth2Client, corev1.EventTypeWarning,
				"Failed", "Failed to reconcile client secret: %s", err)

			r.markFailed(ctx, &oauth2Client,
				fmt.Errorf("failed to reconcile client secret: %w", err))

			return ctrl.Result{}, fmt.Errorf("failed to reconcile client secret: %w", err)
		}
	}

	if oauth2Client.Status.Phase != dexv1alpha1.DexOAuth2ClientPhaseReady {
		r.Recorder.Event(&oauth2Client, corev1.EventTypeNormal,
			"Ready", "Successfully created or updated")

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
	err := updater.UpdateStatus(ctx, r.Client, client.ObjectKeyFromObject(oauth2Client), oauth2Client, func() error {
		oauth2Client.Status.ObservedGeneration = oauth2Client.ObjectMeta.Generation
		oauth2Client.Status.Phase = dexv1alpha1.DexOAuth2ClientPhasePending

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to mark as pending: %w", err)
	}

	return nil
}

func (r *DexOAuth2ClientReconciler) markReady(ctx context.Context, oauth2Client *dexv1alpha1.DexOAuth2Client) error {
	err := updater.UpdateStatus(ctx, r.Client, client.ObjectKeyFromObject(oauth2Client), oauth2Client, func() error {
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

	updateErr := updater.UpdateStatus(ctx, r.Client, client.ObjectKeyFromObject(oauth2Client), oauth2Client, func() error {
		oauth2Client.Status.ObservedGeneration = oauth2Client.Generation
		oauth2Client.Status.Phase = dexv1alpha1.DexOAuth2ClientPhaseFailed
		oauth2Client.Status.Reason = err.Error()

		return nil
	})
	if updateErr != nil {
		logger.Error("Failed to mark as failed", zap.Error(updateErr))
	}
}

func (r *DexOAuth2ClientReconciler) setOwner(ctx context.Context, oauth2Client *dexv1alpha1.DexOAuth2Client, idp *dexv1alpha1.DexIdentityProvider) error {
	// Native owner references don't work across namespaces and it's very often
	// that the client and identity provider are in different namespaces. So we have
	// our own little owner reference implementation.
	_, err := controllerutil.CreateOrPatch(ctx, r.Client, idp, func() error {
		var alreadyOwned bool
		for _, ref := range idp.Status.ClientRefs {
			if ref.Namespace == oauth2Client.Namespace && ref.Name == oauth2Client.Name {
				alreadyOwned = true
				break
			}
		}

		if !alreadyOwned {
			idp.Status.ClientRefs = append(idp.Status.ClientRefs, api.DexOAuth2ClientReference{
				Name:      oauth2Client.Name,
				Namespace: oauth2Client.Namespace,
			})
		}

		return nil
	})

	return err
}

func (r *DexOAuth2ClientReconciler) clientSecretTemplate(oauth2Client *dexv1alpha1.DexOAuth2Client, oauth2ClientID, oauth2ClientSecret string) (*corev1.Secret, error) {
	secret := corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: corev1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      oauth2Client.Spec.SecretName,
			Namespace: oauth2Client.Namespace,
			Labels:    make(map[string]string),
		},
		Data: map[string][]byte{
			"id":     []byte(oauth2ClientID),
			"secret": []byte(oauth2ClientSecret),
		},
	}

	if err := controllerutil.SetControllerReference(oauth2Client, &secret, r.Scheme); err != nil {
		return nil, fmt.Errorf("failed to set controller reference: %w", err)
	}

	for k, v := range oauth2Client.ObjectMeta.Labels {
		secret.ObjectMeta.Labels[k] = v
	}

	secret.ObjectMeta.Labels["app.kubernetes.io/name"] = "oauth2client"
	secret.ObjectMeta.Labels["app.kubernetes.io/instance"] = oauth2Client.Name
	secret.ObjectMeta.Labels["app.kubernetes.io/managed-by"] = "dex-operator"

	return &secret, nil
}
