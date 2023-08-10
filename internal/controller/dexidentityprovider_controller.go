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
	"crypto/sha256"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"time"

	"dario.cat/mergo"
	dexv1alpha1 "github.com/gpu-ninja/dex-operator/api/v1alpha1"
	"github.com/gpu-ninja/dex-operator/internal/dex"
	"github.com/gpu-ninja/operator-utils/retryable"
	"github.com/gpu-ninja/operator-utils/zaplogr"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// Allow recording of events.
// +kubebuilder:rbac:groups="",resources=events,verbs=get;list;watch;create;update;patch

// Need to be able to read secrets to get password refs, and store dex config.
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete

// Need to be able to manage statefulsets and services.
//+kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;create;update;patch;delete

//+kubebuilder:rbac:groups=dex.gpu-ninja.com,resources=dexidentityproviders,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=dex.gpu-ninja.com,resources=dexidentityproviders/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=dex.gpu-ninja.com,resources=dexidentityproviders/finalizers,verbs=update

const (
	finalizerName          = "finalizer.dex.gpu-ninja.com"
	reconcileRetryInterval = 5 * time.Second
)

// DexIdentityProviderReconciler reconciles a DexIdentityProvider object
type DexIdentityProviderReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	EventRecorder record.EventRecorder
}

func (r *DexIdentityProviderReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := zaplogr.FromContext(ctx)

	logger.Info("Reconciling Dex Identity Provider")

	var idp dexv1alpha1.DexIdentityProvider
	if err := r.Get(ctx, req.NamespacedName, &idp); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, err
	}

	if !controllerutil.ContainsFinalizer(&idp, finalizerName) {
		logger.Info("Adding Finalizer")

		_, err := controllerutil.CreateOrPatch(ctx, r.Client, &idp, func() error {
			controllerutil.AddFinalizer(&idp, finalizerName)

			return nil
		})
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to add finalizer: %w", err)
		}
	}

	if !idp.ObjectMeta.DeletionTimestamp.IsZero() {
		logger.Info("Deleting Dex Identity Provider")

		if controllerutil.ContainsFinalizer(&idp, finalizerName) {
			logger.Info("Removing Finalizer")

			_, err := controllerutil.CreateOrPatch(ctx, r.Client, &idp, func() error {
				controllerutil.RemoveFinalizer(&idp, finalizerName)

				return nil
			})
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to remove finalizer: %w", err)
			}
		}

		return ctrl.Result{}, nil
	}

	// Make sure all references are resolvable.
	if err := idp.ResolveReferences(ctx, r.Client, r.Scheme); err != nil {
		if retryable.IsRetryable(err) {
			logger.Info("Not all references are resolvable, requeuing")

			r.EventRecorder.Event(&idp, corev1.EventTypeWarning,
				"NotReady", "Not all references are resolvable")

			if err := r.markPending(ctx, &idp); err != nil {
				return ctrl.Result{}, err
			}

			return ctrl.Result{RequeueAfter: reconcileRetryInterval}, nil
		}

		logger.Error("Failed to resolve references", zap.Error(err))

		r.EventRecorder.Eventf(&idp, corev1.EventTypeWarning,
			"Failed", "Failed to resolve references: %s", err)

		r.markFailed(ctx, &idp, fmt.Errorf("failed to resolve references: %w", err))

		return ctrl.Result{}, nil
	}

	if idp.Status.Phase == dexv1alpha1.DexIdentityProviderPhaseFailed {
		logger.Info("Dex Identity Provider is in failed state, ignoring")

		return ctrl.Result{}, nil
	}

	logger.Info("Creating or updating Dex Identity Provider")

	configSecretName, err := r.saveDexConfig(ctx, &idp)
	if err != nil {
		logger.Error("Failed to render Dex config", zap.Error(err))

		r.EventRecorder.Eventf(&idp, corev1.EventTypeWarning,
			"Failed", "Failed to render Dex config: %s", err)

		r.markFailed(ctx, &idp, fmt.Errorf("failed to render dex config: %w", err))

		return ctrl.Result{}, nil
	}

	logger.Info("Dex config saved", zap.String("secret", configSecretName))

	statefulSetNamespaceName := types.NamespacedName{Name: idp.Name, Namespace: idp.Namespace}
	statefulSet := appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      statefulSetNamespaceName.Name,
			Namespace: statefulSetNamespaceName.Namespace,
		},
	}

	var creatingStatefulSet bool
	if err := r.Get(ctx, statefulSetNamespaceName, &statefulSet); err != nil && errors.IsNotFound(err) {
		creatingStatefulSet = true
	}

	logger.Info("Reconciling Dex Identity Provider StatefulSet",
		zap.Bool("creating", creatingStatefulSet))

	statefulSetOpResult, err := controllerutil.CreateOrPatch(ctx, r.Client, &statefulSet, func() error {
		volumes, volumeMounts, err := r.getDexCertificateVolumes(ctx, &idp)
		if err != nil {
			return fmt.Errorf("failed to get dex volume mounts: %w", err)
		}

		volumes = append(volumes, corev1.Volume{
			Name: "dex-config",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: configSecretName,
				},
			},
		})

		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      "dex-config",
			MountPath: "/etc/dex/config.yaml",
			SubPath:   "config.yaml",
			ReadOnly:  true,
		})

		var volumeClaimTemplates []corev1.PersistentVolumeClaim
		if idp.Spec.LocalStorage != nil {
			storageSize, err := resource.ParseQuantity(idp.Spec.LocalStorage.Size)
			if err != nil {
				return fmt.Errorf("failed to parse local storage size: %w", err)
			}

			volumeClaimTemplates = append(volumeClaimTemplates, corev1.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name: "dex-data",
				},
				Spec: corev1.PersistentVolumeClaimSpec{
					StorageClassName: idp.Spec.LocalStorage.StorageClassName,
					AccessModes: []corev1.PersistentVolumeAccessMode{
						corev1.ReadWriteOnce,
					},
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceStorage: storageSize,
						},
					},
				},
			})

			volumeMounts = append(volumeMounts, corev1.VolumeMount{
				Name:      "dex-data",
				MountPath: idp.Spec.LocalStorage.MountPath,
			})
		}

		ports, err := r.getDexPorts(&idp)
		if err != nil {
			return fmt.Errorf("failed to get dex ports: %w", err)
		}

		var readinessProbe *corev1.Probe
		for _, port := range ports {
			if port.Name == "http" {
				readinessProbe = &corev1.Probe{
					ProbeHandler: corev1.ProbeHandler{
						HTTPGet: &corev1.HTTPGetAction{
							Path: "/healthz",
							Port: intstr.IntOrString{IntVal: port.ContainerPort},
						},
					},
					InitialDelaySeconds: 5,
					PeriodSeconds:       10,
				}

				break
			} else if port.Name == "https" {
				readinessProbe = &corev1.Probe{
					ProbeHandler: corev1.ProbeHandler{
						HTTPGet: &corev1.HTTPGetAction{
							Path:   "/healthz",
							Port:   intstr.IntOrString{IntVal: port.ContainerPort},
							Scheme: corev1.URISchemeHTTPS,
						},
					},
					InitialDelaySeconds: 5,
					PeriodSeconds:       10,
				}

				break
			}
		}

		if err := controllerutil.SetOwnerReference(&idp, &statefulSet, r.Scheme); err != nil {
			return fmt.Errorf("failed to set owner reference: %w", err)
		}

		if statefulSet.ObjectMeta.Labels == nil {
			statefulSet.ObjectMeta.Labels = make(map[string]string)
		}

		for k, v := range idp.ObjectMeta.Labels {
			statefulSet.ObjectMeta.Labels[k] = v
		}

		replicas := idp.Spec.Replicas
		if replicas == nil {
			replicas = ptr.To(int32(1))
		}

		spec := appsv1.StatefulSetSpec{
			Replicas:        replicas,
			ServiceName:     "dex",
			MinReadySeconds: 10,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app.kubernetes.io/name":     "dex",
					"app.kubernetes.io/instance": idp.Name,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app.kubernetes.io/name":     "dex",
						"app.kubernetes.io/instance": idp.Name,
					},
				},
				Spec: corev1.PodSpec{
					TerminationGracePeriodSeconds: ptr.To(int64(10)),
					Containers: []corev1.Container{
						{
							Name:           "dex",
							Image:          idp.Spec.Image,
							Command:        []string{"dex"},
							Args:           []string{"serve", "/etc/dex/config.yaml"},
							VolumeMounts:   volumeMounts,
							Ports:          ports,
							ReadinessProbe: readinessProbe,
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("100m"),
									corev1.ResourceMemory: resource.MustParse("32Mi"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("1"),
									corev1.ResourceMemory: resource.MustParse("256Mi"),
								},
							},
						},
					},
					Volumes: volumes,
				},
			},
			VolumeClaimTemplates: volumeClaimTemplates,
		}

		if creatingStatefulSet {
			statefulSet.Spec = spec
		} else if err := mergo.Merge(&statefulSet.Spec, spec, mergo.WithOverride, mergo.WithSliceDeepCopy); err != nil {
			return fmt.Errorf("failed to merge spec: %w", err)
		}

		return nil
	})
	if err != nil {
		logger.Error("Failed to reconcile Dex Identity Provider StatefulSet", zap.Error(err))

		r.EventRecorder.Eventf(&idp, corev1.EventTypeWarning,
			"Failed", "Failed to reconcile Dex Identity Provider StatefulSet: %v", err)

		r.markFailed(ctx, &idp,
			fmt.Errorf("failed to reconcile dex identity provider statefulset: %w", err))

		return ctrl.Result{}, nil
	}

	if statefulSetOpResult != controllerutil.OperationResultNone {
		logger.Info("Dex Identity Provider StatefulSet successfully reconciled, marking as pending",
			zap.String("operation", string(statefulSetOpResult)))

		if err := r.markPending(ctx, &idp); err != nil {
			return ctrl.Result{}, err
		}
	}

	webServiceNamespaceName := types.NamespacedName{Name: idp.Name, Namespace: idp.Namespace}
	webService := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      webServiceNamespaceName.Name,
			Namespace: webServiceNamespaceName.Namespace,
		},
	}

	var creatingWebService bool
	if err := r.Client.Get(ctx, webServiceNamespaceName, &webService); err != nil && errors.IsNotFound(err) {
		creatingWebService = true
	}

	logger.Info("Reconciling Dex Identity Provider Web Service", zap.Bool("creating", creatingWebService))

	webServiceOpResult, err := controllerutil.CreateOrPatch(ctx, r.Client, &webService, func() error {
		var ports []corev1.ServicePort

		if idp.Spec.Web.HTTP != "" {
			ports = append(ports, corev1.ServicePort{
				Name:       "http",
				Port:       int32(80),
				TargetPort: intstr.FromString("http"),
			})
		}

		if idp.Spec.Web.HTTPS != "" {
			ports = append(ports, corev1.ServicePort{
				Name:       "https",
				Port:       int32(443),
				TargetPort: intstr.FromString("https"),
			})
		}

		if err := controllerutil.SetControllerReference(&idp, &webService, r.Scheme); err != nil {
			return fmt.Errorf("failed to set controller reference: %w", err)
		}

		if webService.ObjectMeta.Labels == nil {
			webService.ObjectMeta.Labels = make(map[string]string)
		}

		for k, v := range idp.ObjectMeta.Labels {
			webService.ObjectMeta.Labels[k] = v
		}

		spec := corev1.ServiceSpec{
			Selector: map[string]string{
				"app.kubernetes.io/name":     "dex",
				"app.kubernetes.io/instance": idp.Name,
			},
			Ports: ports,
		}

		if creatingWebService {
			webService.Spec = spec
		} else {
			if err := mergo.Merge(&webService.Spec, spec, mergo.WithOverride, mergo.WithSliceDeepCopy); err != nil {
				return fmt.Errorf("failed to merge spec: %w", err)
			}
		}

		return nil
	})
	if err != nil {
		logger.Error("Failed to reconcile Dex Identity Provider Web Service", zap.Error(err))

		r.EventRecorder.Eventf(&idp, corev1.EventTypeWarning,
			"Failed", "Failed to reconcile dex idp web service: %v", err)

		r.markFailed(ctx, &idp, fmt.Errorf("failed to reconcile dex idp web service: %w", err))

		return ctrl.Result{}, nil
	}

	if webServiceOpResult != controllerutil.OperationResultNone {
		logger.Info("Dex Identity Provider Web Service successfully reconciled",
			zap.String("operation", string(webServiceOpResult)))
	}

	apiServiceNamespaceName := types.NamespacedName{Name: idp.Name + "-api", Namespace: idp.Namespace}
	apiService := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      apiServiceNamespaceName.Name,
			Namespace: apiServiceNamespaceName.Namespace,
		},
	}

	var creatingAPIService bool
	if err := r.Client.Get(ctx, apiServiceNamespaceName, &apiService); err != nil && errors.IsNotFound(err) {
		creatingAPIService = true
	}

	logger.Info("Reconciling Dex Identity Provider API Service", zap.Bool("creating", creatingAPIService))

	apiServiceOpResult, err := controllerutil.CreateOrPatch(ctx, r.Client, &apiService, func() error {
		var ports []corev1.ServicePort

		if idp.Spec.GRPC.CertificateSecretRef != nil {
			ports = append(ports, corev1.ServicePort{
				Name:       "https",
				Port:       int32(443),
				TargetPort: intstr.FromString("grpc"),
			})
		} else {
			ports = append(ports, corev1.ServicePort{
				Name:       "http",
				Port:       int32(80),
				TargetPort: intstr.FromString("grpc"),
			})
		}

		if err := controllerutil.SetControllerReference(&idp, &apiService, r.Scheme); err != nil {
			return fmt.Errorf("failed to set controller reference: %w", err)
		}

		if apiService.ObjectMeta.Labels == nil {
			apiService.ObjectMeta.Labels = make(map[string]string)
		}

		for k, v := range idp.ObjectMeta.Labels {
			apiService.ObjectMeta.Labels[k] = v
		}

		spec := corev1.ServiceSpec{
			Selector: map[string]string{
				"app.kubernetes.io/name":     "dex",
				"app.kubernetes.io/instance": idp.Name,
			},
			Ports: ports,
		}

		if creatingAPIService {
			apiService.Spec = spec
		} else {
			if err := mergo.Merge(&apiService.Spec, spec, mergo.WithOverride, mergo.WithSliceDeepCopy); err != nil {
				return fmt.Errorf("failed to merge spec: %w", err)
			}
		}

		return nil
	})
	if err != nil {
		logger.Error("Failed to reconcile Dex Identity Provider API Service", zap.Error(err))

		r.EventRecorder.Eventf(&idp, corev1.EventTypeWarning,
			"Failed", "Failed to reconcile dex idp api service: %v", err)

		r.markFailed(ctx, &idp, fmt.Errorf("failed to reconcile dex idp api service: %w", err))

		return ctrl.Result{}, nil
	}

	if apiServiceOpResult != controllerutil.OperationResultNone {
		logger.Info("Dex Identity Provider API Service successfully reconciled",
			zap.String("operation", string(apiServiceOpResult)))
	}

	if statefulSet.Status.ReadyReplicas != *statefulSet.Spec.Replicas {
		logger.Info("Waiting for Dex Identity Provider to become ready")

		r.EventRecorder.Event(&idp, corev1.EventTypeNormal,
			"Pending", "Waiting for dex idp to become ready")

		if err := r.markPending(ctx, &idp); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{RequeueAfter: reconcileRetryInterval}, nil
	}

	if idp.Status.Phase != dexv1alpha1.DexIdentityProviderPhaseReady {
		r.EventRecorder.Event(&idp, corev1.EventTypeNormal,
			"Created", "Successfully created")

		if err := r.markReady(ctx, &idp); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func (r *DexIdentityProviderReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&dexv1alpha1.DexIdentityProvider{}).
		Owns(&appsv1.StatefulSet{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}

func (r *DexIdentityProviderReconciler) saveDexConfig(ctx context.Context, idp *dexv1alpha1.DexIdentityProvider) (string, error) {
	config, err := dex.ConfigFromCR(ctx, r.Client, r.Scheme, idp)
	if err != nil {
		return "", fmt.Errorf("failed to generate dex config: %w", err)
	}

	configYAML, err := yaml.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("failed to marshal dex config: %w", err)
	}

	configHash := fmt.Sprintf("%x", sha256.Sum256([]byte(configYAML)))

	configSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", idp.Name, configHash[:10]),
			Namespace: idp.Namespace,
		},
	}

	_, err = controllerutil.CreateOrPatch(ctx, r.Client, configSecret, func() error {
		if err := controllerutil.SetControllerReference(idp, configSecret, r.Scheme); err != nil {
			return fmt.Errorf("failed to set controller reference: %w", err)
		}

		configSecret.Type = corev1.SecretTypeOpaque
		configSecret.Data = map[string][]byte{
			"config.yaml": []byte(configYAML),
		}

		return nil
	})
	if err != nil {
		return "", fmt.Errorf("failed to create or update config secret: %w", err)
	}

	return configSecret.Name, nil
}

func (r *DexIdentityProviderReconciler) markPending(ctx context.Context, idp *dexv1alpha1.DexIdentityProvider) error {
	updatedConditions := make([]metav1.Condition, len(idp.Status.Conditions))
	copy(updatedConditions, idp.Status.Conditions)

	meta.SetStatusCondition(&updatedConditions, metav1.Condition{
		Type:    string(dexv1alpha1.DexIdentityProviderConditionTypePending),
		Status:  metav1.ConditionTrue,
		Reason:  "Pending",
		Message: "Dex Identity Provider is pending",
	})

	_, err := controllerutil.CreateOrPatch(ctx, r.Client, idp, func() error {
		idp.Status.ObservedGeneration = idp.Generation
		idp.Status.Phase = dexv1alpha1.DexIdentityProviderPhasePending
		idp.Status.Conditions = updatedConditions

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to mark as pending: %w", err)
	}

	return nil
}

func (r *DexIdentityProviderReconciler) markReady(ctx context.Context, idp *dexv1alpha1.DexIdentityProvider) error {
	updatedConditions := make([]metav1.Condition, len(idp.Status.Conditions))
	copy(updatedConditions, idp.Status.Conditions)

	meta.SetStatusCondition(&updatedConditions, metav1.Condition{
		Type:    string(dexv1alpha1.DexIdentityProviderConditionTypeReady),
		Status:  metav1.ConditionTrue,
		Reason:  "Ready",
		Message: "Dex Identity Provider is ready",
	})

	_, err := controllerutil.CreateOrPatch(ctx, r.Client, idp, func() error {
		idp.Status.ObservedGeneration = idp.Generation
		idp.Status.Phase = dexv1alpha1.DexIdentityProviderPhaseReady
		idp.Status.Conditions = updatedConditions

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to mark as ready: %w", err)
	}

	return nil
}

func (r *DexIdentityProviderReconciler) markFailed(ctx context.Context, idp *dexv1alpha1.DexIdentityProvider, err error) {
	logger := zaplogr.FromContext(ctx)

	updatedConditions := make([]metav1.Condition, len(idp.Status.Conditions))
	copy(updatedConditions, idp.Status.Conditions)

	meta.SetStatusCondition(&updatedConditions, metav1.Condition{
		Type:    string(dexv1alpha1.DexIdentityProviderConditionTypeFailed),
		Status:  metav1.ConditionTrue,
		Reason:  "Failed",
		Message: err.Error(),
	})

	_, updateErr := controllerutil.CreateOrPatch(ctx, r.Client, idp, func() error {
		idp.Status.ObservedGeneration = idp.Generation
		idp.Status.Phase = dexv1alpha1.DexIdentityProviderPhaseFailed
		idp.Status.Conditions = updatedConditions

		return nil
	})
	if updateErr != nil {
		logger.Error("Failed to mark as failed", zap.Error(updateErr))
	}
}

func (r *DexIdentityProviderReconciler) getDexCertificateVolumes(ctx context.Context, idp *dexv1alpha1.DexIdentityProvider) ([]corev1.Volume, []corev1.VolumeMount, error) {
	var volumeMap = map[string]corev1.Volume{}
	var volumeMounts []corev1.VolumeMount

	addSecretVolume := func(name, secretName, mountPath string, caOnly bool) {
		if _, exists := volumeMap[secretName]; !exists {
			volumeMap[secretName] = corev1.Volume{
				Name: name,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: secretName,
					},
				},
			}

			volumeMount := corev1.VolumeMount{
				Name:      name,
				MountPath: mountPath,
				ReadOnly:  true,
			}

			if caOnly {
				volumeMount.MountPath = filepath.Join(mountPath, "ca.crt")
				volumeMount.SubPath = "ca.crt"
			}

			volumeMounts = append(volumeMounts, volumeMount)
		}
	}

	if idp.Spec.Web.CertificateSecretRef != nil {
		addSecretVolume("web-cert", idp.Spec.Web.CertificateSecretRef.Name,
			filepath.Join(dex.CertsBase, idp.Spec.Web.CertificateSecretRef.Name), false)
	}

	if idp.Spec.GRPC.CertificateSecretRef != nil {
		addSecretVolume("grpc-cert", idp.Spec.GRPC.CertificateSecretRef.Name,
			filepath.Join(dex.CertsBase, idp.Spec.GRPC.CertificateSecretRef.Name), false)
	}

	if idp.Spec.GRPC.ClientCASecretRef != nil {
		addSecretVolume("grpc-client-ca", idp.Spec.GRPC.ClientCASecretRef.Name,
			filepath.Join(dex.CertsBase, idp.Spec.GRPC.ClientCASecretRef.Name), true)
	}

	if idp.Spec.Storage.Type == dexv1alpha1.DexIdentityProviderStorageTypePostgres &&
		idp.Spec.Storage.Postgres != nil &&
		idp.Spec.Storage.Postgres.SSL != nil {
		if idp.Spec.Storage.Postgres.SSL.CASecretRef != nil {
			addSecretVolume("postgres-ca", idp.Spec.Storage.Postgres.SSL.CASecretRef.Name,
				filepath.Join(dex.CertsBase, idp.Spec.Storage.Postgres.SSL.CASecretRef.Name), true)
		}

		if idp.Spec.Storage.Postgres.SSL.ClientCertificateSecretRef != nil {
			addSecretVolume("postgres-client-cert", idp.Spec.Storage.Postgres.SSL.ClientCertificateSecretRef.Name,
				filepath.Join(dex.CertsBase, idp.Spec.Storage.Postgres.SSL.ClientCertificateSecretRef.Name), false)
		}
	}

	for _, connector := range idp.Spec.Connectors {
		if connector.Type == dexv1alpha1.DexIdentityProviderConnectorTypeLDAP && connector.LDAP != nil {
			if connector.LDAP.CASecretRef != nil {
				addSecretVolume("ldap-ca", connector.LDAP.CASecretRef.Name,
					filepath.Join(dex.CertsBase, connector.LDAP.CASecretRef.Name), true)
			}

			if connector.LDAP.ClientCertificateSecretRef != nil {
				addSecretVolume("ldap-client-cert", connector.LDAP.ClientCertificateSecretRef.Name,
					filepath.Join(dex.CertsBase, connector.LDAP.ClientCertificateSecretRef.Name), false)
			}
		} else if connector.Type == dexv1alpha1.DexIdentityProviderConnectorTypeOIDC && connector.OIDC != nil {
			if connector.OIDC.CASecretRef != nil {
				addSecretVolume("oidc-ca", connector.OIDC.CASecretRef.Name,
					filepath.Join(dex.CertsBase, connector.OIDC.CASecretRef.Name), true)
			}
		}
	}

	var volumes []corev1.Volume
	for _, volume := range volumeMap {
		volumes = append(volumes, volume)
	}

	return volumes, volumeMounts, nil
}

func (r *DexIdentityProviderReconciler) getDexPorts(idp *dexv1alpha1.DexIdentityProvider) ([]corev1.ContainerPort, error) {
	var ports []corev1.ContainerPort

	if idp.Spec.Web.HTTP != "" {
		_, httpPortString, err := net.SplitHostPort(idp.Spec.Web.HTTP)
		if err != nil {
			return nil, fmt.Errorf("failed to parse http address: %w", err)
		}

		httpPort, err := strconv.Atoi(httpPortString)
		if err != nil {
			return nil, fmt.Errorf("failed to parse http port: %w", err)
		}

		ports = append(ports, corev1.ContainerPort{
			Name:          "http",
			ContainerPort: int32(httpPort),
			Protocol:      corev1.ProtocolTCP,
		})
	}

	if idp.Spec.Web.HTTPS != "" {
		_, httpsPortString, err := net.SplitHostPort(idp.Spec.Web.HTTPS)
		if err != nil {
			return nil, fmt.Errorf("failed to parse https address: %w", err)
		}

		httpsPort, err := strconv.Atoi(httpsPortString)
		if err != nil {
			return nil, fmt.Errorf("failed to parse https port: %w", err)
		}

		ports = append(ports, corev1.ContainerPort{
			Name:          "https",
			ContainerPort: int32(httpsPort),
			Protocol:      corev1.ProtocolTCP,
		})
	}

	_, grpcPortString, err := net.SplitHostPort(idp.Spec.GRPC.Addr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse grpc address: %w", err)
	}

	grpcPort, err := strconv.Atoi(grpcPortString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse grpc port: %w", err)
	}

	ports = append(ports, corev1.ContainerPort{
		Name:          "grpc",
		ContainerPort: int32(grpcPort),
		Protocol:      corev1.ProtocolTCP,
	})

	return ports, nil
}
