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
	"path/filepath"
	"sort"
	"time"

	dexv1alpha1 "github.com/gpu-ninja/dex-operator/api/v1alpha1"
	"github.com/gpu-ninja/dex-operator/internal/dex"
	"github.com/gpu-ninja/operator-utils/updater"
	"github.com/gpu-ninja/operator-utils/zaplogr"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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

// Need to be able to manage statefulsets, services, and service monitors.
//+kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=monitoring.coreos.com,resources=servicemonitors,verbs=get;list;watch;create;update;patch;delete

//+kubebuilder:rbac:groups=dex.gpu-ninja.com,resources=dexidentityproviders,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=dex.gpu-ninja.com,resources=dexidentityproviders/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=dex.gpu-ninja.com,resources=dexidentityproviders/finalizers,verbs=update

const (
	// FinalizerName is the name of the finalizer used by controllers.
	FinalizerName = "dex.gpu-ninja.com/finalizer"
	// reconcileRetryInterval is the interval at which the controller will retry
	// to reconcile a pending resource.
	reconcileRetryInterval = 10 * time.Second
)

// DexIdentityProviderReconciler reconciles a DexIdentityProvider object
type DexIdentityProviderReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

func (r *DexIdentityProviderReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := zaplogr.FromContext(ctx)

	logger.Info("Reconciling")

	var idp dexv1alpha1.DexIdentityProvider
	if err := r.Get(ctx, req.NamespacedName, &idp); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, err
	}

	if !controllerutil.ContainsFinalizer(&idp, FinalizerName) {
		logger.Info("Adding Finalizer")

		_, err := controllerutil.CreateOrPatch(ctx, r.Client, &idp, func() error {
			controllerutil.AddFinalizer(&idp, FinalizerName)

			return nil
		})
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to add finalizer: %w", err)
		}
	}

	if !idp.GetDeletionTimestamp().IsZero() {
		logger.Info("Deleting")

		for _, ref := range idp.Status.ClientRefs {
			referencedClient := dexv1alpha1.DexOAuth2Client{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ref.Name,
					Namespace: ref.Namespace,
				},
			}

			if err := r.Client.Delete(ctx, &referencedClient); err != nil && !apierrors.IsNotFound(err) {
				// Don't block deletion.
				logger.Error("Failed to cleanup referenced client, skipping deletion", zap.Error(err))
			}
		}

		if controllerutil.ContainsFinalizer(&idp, FinalizerName) {
			logger.Info("Removing Finalizer")

			_, err := controllerutil.CreateOrPatch(ctx, r.Client, &idp, func() error {
				controllerutil.RemoveFinalizer(&idp, FinalizerName)

				return nil
			})
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to remove finalizer: %w", err)
			}
		}

		return ctrl.Result{}, nil
	}

	ok, err := idp.ResolveReferences(ctx, r.Client, r.Scheme)
	if !ok && err == nil {
		logger.Info("Not all references are resolvable, requeuing")

		r.Recorder.Event(&idp, corev1.EventTypeWarning,
			"NotReady", "Not all references are resolvable")

		if err := r.markPending(ctx, &idp); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{RequeueAfter: reconcileRetryInterval}, nil
	} else if err != nil {
		r.Recorder.Eventf(&idp, corev1.EventTypeWarning,
			"Failed", "Failed to resolve references: %s", err)

		r.markFailed(ctx, &idp,
			fmt.Errorf("failed to resolve references: %w", err))

		return ctrl.Result{}, fmt.Errorf("failed to resolve references: %w", err)
	}

	logger.Info("Creating or updating")

	configSecret, err := r.configSecretTemplate(ctx, &idp)
	if err != nil {
		r.Recorder.Eventf(&idp, corev1.EventTypeWarning,
			"Failed", "Failed to generate dex config: %s", err)

		r.markFailed(ctx, &idp,
			fmt.Errorf("failed to generate dex config: %w", err))

		return ctrl.Result{}, fmt.Errorf("failed to generate dex config: %w", err)
	}

	if _, err := updater.CreateOrUpdateFromTemplate(ctx, r.Client, configSecret); err != nil {
		r.Recorder.Eventf(&idp, corev1.EventTypeWarning,
			"Failed", "Failed to reconcile dex config: %s", err)

		r.markFailed(ctx, &idp,
			fmt.Errorf("failed to reconcile dex config: %w", err))

		return ctrl.Result{}, fmt.Errorf("failed to reconcile dex config: %w", err)
	}

	logger.Info("Dex config saved", zap.String("secret", configSecret.Name))

	logger.Info("Reconciling statefulset")

	sts, err := r.statefulSetTemplate(&idp, configSecret.Name)
	if err != nil {
		r.Recorder.Eventf(&idp, corev1.EventTypeWarning,
			"Failed", "Failed to generate statefulset template: %s", err)

		r.markFailed(ctx, &idp,
			fmt.Errorf("failed to generate statefulset template: %w", err))

		return ctrl.Result{}, fmt.Errorf("failed to generate statefulset template: %w", err)
	}

	if _, err := updater.CreateOrUpdateFromTemplate(ctx, r.Client, sts); err != nil {
		r.Recorder.Eventf(&idp, corev1.EventTypeWarning,
			"Failed", "Failed to reconcile statefulset: %s", err)

		r.markFailed(ctx, &idp,
			fmt.Errorf("failed to reconcile statefulset: %w", err))

		return ctrl.Result{}, fmt.Errorf("failed to reconcile statefulset: %w", err)
	}

	logger.Info("Reconciling web service")

	webSvc, err := r.webServiceTemplate(&idp)
	if err != nil {
		r.Recorder.Eventf(&idp, corev1.EventTypeWarning,
			"Failed", "Failed to generate web service template: %s", err)

		r.markFailed(ctx, &idp,
			fmt.Errorf("failed to generate web service template: %w", err))

		return ctrl.Result{}, fmt.Errorf("failed to generate web service template: %w", err)
	}

	if _, err := updater.CreateOrUpdateFromTemplate(ctx, r.Client, webSvc); err != nil {
		r.Recorder.Eventf(&idp, corev1.EventTypeWarning,
			"Failed", "Failed to reconcile web service: %s", err)

		r.markFailed(ctx, &idp,
			fmt.Errorf("failed to reconcile web service: %w", err))

		return ctrl.Result{}, fmt.Errorf("failed to reconcile web service: %w", err)
	}

	logger.Info("Reconciling API Service")

	apiSvc, err := r.apiServiceTemplate(&idp)
	if err != nil {
		r.Recorder.Eventf(&idp, corev1.EventTypeWarning,
			"Failed", "Failed to generate api service template: %s", err)

		r.markFailed(ctx, &idp,
			fmt.Errorf("failed to generate api service template: %w", err))

		return ctrl.Result{}, fmt.Errorf("failed to generate api service template: %w", err)
	}

	if _, err := updater.CreateOrUpdateFromTemplate(ctx, r.Client, apiSvc); err != nil {
		r.Recorder.Eventf(&idp, corev1.EventTypeWarning,
			"Failed", "Failed to reconcile api service: %s", err)

		r.markFailed(ctx, &idp,
			fmt.Errorf("failed to reconcile api service: %w", err))

		return ctrl.Result{}, fmt.Errorf("failed to reconcile api service: %w", err)
	}

	logger.Info("Reconciling metrics service")

	metricsSvc, err := r.metricsServiceTemplate(&idp)
	if err != nil {
		r.Recorder.Eventf(&idp, corev1.EventTypeWarning,
			"Failed", "Failed to generate metrics service template: %s", err)

		r.markFailed(ctx, &idp,
			fmt.Errorf("failed to generate metrics service template: %w", err))

		return ctrl.Result{}, fmt.Errorf("failed to generate metrics service template: %w", err)
	}

	if _, err := updater.CreateOrUpdateFromTemplate(ctx, r.Client, metricsSvc); err != nil {
		r.Recorder.Eventf(&idp, corev1.EventTypeWarning,
			"Failed", "Failed to reconcile metrics service: %s", err)

		r.markFailed(ctx, &idp,
			fmt.Errorf("failed to reconcile metrics service: %w", err))

		return ctrl.Result{}, fmt.Errorf("failed to reconcile metrics service: %w", err)
	}

	if idp.Spec.Metrics != nil && idp.Spec.Metrics.Enabled {
		logger.Info("Reconciling service monitor")

		svcMonitor, err := r.serviceMonitorTemplate(&idp)
		if err != nil {
			r.Recorder.Eventf(&idp, corev1.EventTypeWarning,
				"Failed", "Failed to generate service monitor template: %s", err)

			r.markFailed(ctx, &idp,
				fmt.Errorf("failed to generate service monitor template: %w", err))

			return ctrl.Result{}, fmt.Errorf("failed to generate service monitor template: %w", err)
		}

		if _, err := updater.CreateOrUpdateFromTemplate(ctx, r.Client, svcMonitor); err != nil {
			r.Recorder.Eventf(&idp, corev1.EventTypeWarning,
				"Failed", "Failed to reconcile service monitor: %s", err)

			r.markFailed(ctx, &idp,
				fmt.Errorf("failed to reconcile service monitor: %w", err))

			return ctrl.Result{}, fmt.Errorf("failed to reconcile service monitor: %w", err)
		}
	} else {
		svcMonitor := monitoringv1.ServiceMonitor{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "dex-" + idp.Name,
				Namespace: idp.Namespace,
			},
		}

		if err := r.Get(ctx, client.ObjectKeyFromObject(&svcMonitor), &svcMonitor); err != nil {
			if !apierrors.IsNotFound(err) {
				r.Recorder.Eventf(&idp, corev1.EventTypeWarning,
					"Failed", "Failed to get service monitor: %s", err)

				r.markFailed(ctx, &idp,
					fmt.Errorf("failed to get service monitor: %w", err))

				return ctrl.Result{}, fmt.Errorf("failed to get service monitor: %w", err)
			}

			// Not found, nothing to do.
		} else {
			logger.Info("Deleting service monitor")

			if err := r.Delete(ctx, &svcMonitor); err != nil {
				r.Recorder.Eventf(&idp, corev1.EventTypeWarning,
					"Failed", "Failed to delete service monitor: %s", err)

				r.markFailed(ctx, &idp,
					fmt.Errorf("failed to delete service monitor: %w", err))

				return ctrl.Result{}, fmt.Errorf("failed to delete service monitor: %w", err)
			}
		}
	}

	logger.Info("Checking if statefulset is ready")

	ready, err := r.isStatefulSetReady(ctx, &idp)
	if err != nil {
		r.Recorder.Eventf(&idp, corev1.EventTypeWarning,
			"Failed", "Failed to check if statefulset is ready: %s", err)

		r.markFailed(ctx, &idp,
			fmt.Errorf("failed to check if statefulset is ready: %w", err))

		return ctrl.Result{}, fmt.Errorf("failed to check if statefulset is ready: %w", err)
	}

	if !ready {
		logger.Info("Waiting for statefulset to become ready")

		r.Recorder.Event(&idp, corev1.EventTypeNormal,
			"Pending", "Waiting for statefulset to become ready")

		if err := r.markPending(ctx, &idp); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{RequeueAfter: reconcileRetryInterval}, nil
	}

	if idp.Status.Phase != dexv1alpha1.DexIdentityProviderPhaseReady {
		r.Recorder.Event(&idp, corev1.EventTypeNormal,
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

func (r *DexIdentityProviderReconciler) markPending(ctx context.Context, idp *dexv1alpha1.DexIdentityProvider) error {
	key := client.ObjectKeyFromObject(idp)
	err := updater.UpdateStatus(ctx, r.Client, key, idp, func() error {
		idp.Status.ObservedGeneration = idp.ObjectMeta.Generation
		idp.Status.Phase = dexv1alpha1.DexIdentityProviderPhasePending

		meta.SetStatusCondition(&idp.Status.Conditions, metav1.Condition{
			Type:               string(dexv1alpha1.DexIdentityProviderConditionTypePending),
			Status:             metav1.ConditionTrue,
			ObservedGeneration: idp.ObjectMeta.Generation,
			Reason:             "Pending",
			Message:            "Dex Identity Provider is pending",
		})

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to mark as pending: %w", err)
	}

	return nil
}

func (r *DexIdentityProviderReconciler) markReady(ctx context.Context, idp *dexv1alpha1.DexIdentityProvider) error {
	key := client.ObjectKeyFromObject(idp)
	err := updater.UpdateStatus(ctx, r.Client, key, idp, func() error {
		idp.Status.ObservedGeneration = idp.ObjectMeta.Generation
		idp.Status.Phase = dexv1alpha1.DexIdentityProviderPhaseReady

		meta.SetStatusCondition(&idp.Status.Conditions, metav1.Condition{
			Type:               string(dexv1alpha1.DexIdentityProviderConditionTypeReady),
			Status:             metav1.ConditionTrue,
			ObservedGeneration: idp.ObjectMeta.Generation,
			Reason:             "Ready",
			Message:            "Dex Identity Provider is ready",
		})

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to mark as ready: %w", err)
	}

	return nil
}

func (r *DexIdentityProviderReconciler) markFailed(ctx context.Context, idp *dexv1alpha1.DexIdentityProvider, err error) {
	logger := zaplogr.FromContext(ctx)

	key := client.ObjectKeyFromObject(idp)
	updateErr := updater.UpdateStatus(ctx, r.Client, key, idp, func() error {
		idp.Status.ObservedGeneration = idp.ObjectMeta.Generation
		idp.Status.Phase = dexv1alpha1.DexIdentityProviderPhaseFailed

		meta.SetStatusCondition(&idp.Status.Conditions, metav1.Condition{
			Type:               string(dexv1alpha1.DexIdentityProviderConditionTypeFailed),
			Status:             metav1.ConditionTrue,
			ObservedGeneration: idp.ObjectMeta.Generation,
			Reason:             "Failed",
			Message:            err.Error(),
		})

		return nil
	})
	if updateErr != nil {
		logger.Error("Failed to mark as failed", zap.Error(updateErr))
	}
}

func (r *DexIdentityProviderReconciler) statefulSetTemplate(idp *dexv1alpha1.DexIdentityProvider, configSecretName string) (*appsv1.StatefulSet, error) {
	volumes, volumeMounts, err := getDexCertificateVolumes(idp)
	if err != nil {
		return nil, fmt.Errorf("failed to get dex volume mounts: %w", err)
	}

	volumes = append(volumes, corev1.Volume{
		Name: "config",
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: configSecretName,
			},
		},
	})

	volumeMounts = append(volumeMounts, corev1.VolumeMount{
		Name:      "config",
		MountPath: "/etc/dex/config.yaml",
		SubPath:   "config.yaml",
		ReadOnly:  true,
	})

	volumeMounts = append(volumeMounts, idp.Spec.VolumeMounts...)

	ports, err := getDexPorts(idp)
	if err != nil {
		return nil, fmt.Errorf("failed to get dex ports: %w", err)
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

	replicas := idp.Spec.Replicas
	if replicas == nil {
		replicas = ptr.To(int32(1))
	}

	sts := appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dex-" + idp.Name,
			Namespace: idp.Namespace,
			Labels:    make(map[string]string),
		},
		Spec: appsv1.StatefulSetSpec{
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
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: ptr.To(true),
						RunAsUser:    ptr.To(int64(1001)),
						RunAsGroup:   ptr.To(int64(1001)),
						FSGroup:      ptr.To(int64(1001)),
					},
					Containers: []corev1.Container{
						{
							Name:           "dex",
							Image:          idp.Spec.Image,
							Command:        []string{"dex"},
							Args:           []string{"serve", "/etc/dex/config.yaml"},
							VolumeMounts:   volumeMounts,
							Ports:          ports,
							ReadinessProbe: readinessProbe,
							Resources:      idp.Spec.Resources,
						},
					},
					Volumes: volumes,
				},
			},
			VolumeClaimTemplates: idp.Spec.VolumeClaimTemplates,
		},
	}

	if err := controllerutil.SetOwnerReference(idp, &sts, r.Scheme); err != nil {
		return nil, fmt.Errorf("failed to set owner reference: %w", err)
	}

	for k, v := range idp.ObjectMeta.Labels {
		sts.ObjectMeta.Labels[k] = v
	}

	sts.ObjectMeta.Labels["app.kubernetes.io/name"] = "dex"
	sts.ObjectMeta.Labels["app.kubernetes.io/instance"] = idp.Name
	sts.ObjectMeta.Labels["app.kubernetes.io/managed-by"] = "dex-operator"

	return &sts, nil
}

func (r *DexIdentityProviderReconciler) isStatefulSetReady(ctx context.Context, idp *dexv1alpha1.DexIdentityProvider) (bool, error) {
	sts := appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dex-" + idp.Name,
			Namespace: idp.Namespace,
		},
	}

	if err := r.Get(ctx, client.ObjectKeyFromObject(&sts), &sts); err != nil {
		return false, fmt.Errorf("failed to get statefulset: %w", err)
	}

	return sts.Status.ReadyReplicas == *sts.Spec.Replicas, nil
}

func (r *DexIdentityProviderReconciler) webServiceTemplate(idp *dexv1alpha1.DexIdentityProvider) (*corev1.Service, error) {
	var ports []corev1.ServicePort

	if idp.Spec.Web.CertificateSecretRef != nil {
		ports = []corev1.ServicePort{{
			Name:       "https",
			Port:       int32(443),
			TargetPort: intstr.FromString("https"),
		}}
	} else {
		ports = []corev1.ServicePort{{
			Name:       "http",
			Port:       int32(80),
			TargetPort: intstr.FromString("http"),
		}}
	}

	svc := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "dex-" + idp.Name,
			Namespace:   idp.Namespace,
			Labels:      make(map[string]string),
			Annotations: idp.Spec.Web.Annotations,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app.kubernetes.io/name":     "dex",
				"app.kubernetes.io/instance": idp.Name,
			},
			Ports: ports,
		},
	}

	if err := controllerutil.SetOwnerReference(idp, &svc, r.Scheme); err != nil {
		return nil, fmt.Errorf("failed to set owner reference: %w", err)
	}

	for k, v := range idp.ObjectMeta.Labels {
		svc.ObjectMeta.Labels[k] = v
	}

	svc.ObjectMeta.Labels["app.kubernetes.io/name"] = "dex"
	svc.ObjectMeta.Labels["app.kubernetes.io/instance"] = idp.Name
	svc.ObjectMeta.Labels["app.kubernetes.io/managed-by"] = "dex-operator"

	return &svc, nil
}

func (r *DexIdentityProviderReconciler) apiServiceTemplate(idp *dexv1alpha1.DexIdentityProvider) (*corev1.Service, error) {
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

	svc := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        fmt.Sprintf("dex-%s-api", idp.Name),
			Namespace:   idp.Namespace,
			Labels:      make(map[string]string),
			Annotations: idp.Spec.GRPC.Annotations,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app.kubernetes.io/name":     "dex",
				"app.kubernetes.io/instance": idp.Name,
			},
			Ports: ports,
		},
	}

	if err := controllerutil.SetControllerReference(idp, &svc, r.Scheme); err != nil {
		return nil, fmt.Errorf("failed to set controller reference: %w", err)
	}

	for k, v := range idp.ObjectMeta.Labels {
		svc.ObjectMeta.Labels[k] = v
	}

	svc.ObjectMeta.Labels["app.kubernetes.io/name"] = "dex"
	svc.ObjectMeta.Labels["app.kubernetes.io/instance"] = idp.Name
	svc.ObjectMeta.Labels["app.kubernetes.io/managed-by"] = "dex-operator"

	return &svc, nil
}

func (r *DexIdentityProviderReconciler) metricsServiceTemplate(idp *dexv1alpha1.DexIdentityProvider) (*corev1.Service, error) {
	svc := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        fmt.Sprintf("dex-%s-metrics", idp.Name),
			Namespace:   idp.Namespace,
			Labels:      make(map[string]string),
			Annotations: idp.Spec.GRPC.Annotations,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app.kubernetes.io/name":     "dex",
				"app.kubernetes.io/instance": idp.Name,
			},
			Ports: []corev1.ServicePort{{
				Name:       "metrics",
				Port:       9090,
				TargetPort: intstr.FromString("metrics"),
			}},
		},
	}

	if err := controllerutil.SetControllerReference(idp, &svc, r.Scheme); err != nil {
		return nil, fmt.Errorf("failed to set controller reference: %w", err)
	}

	for k, v := range idp.ObjectMeta.Labels {
		svc.ObjectMeta.Labels[k] = v
	}

	svc.ObjectMeta.Labels["app.kubernetes.io/name"] = "dex"
	if err := controllerutil.SetControllerReference(idp, &svc, r.Scheme); err != nil {
		return nil, fmt.Errorf("failed to set controller reference: %w", err)
	}

	for k, v := range idp.ObjectMeta.Labels {
		svc.ObjectMeta.Labels[k] = v
	}

	svc.ObjectMeta.Labels["app.kubernetes.io/name"] = "dex"
	svc.ObjectMeta.Labels["app.kubernetes.io/instance"] = idp.Name
	svc.ObjectMeta.Labels["app.kubernetes.io/managed-by"] = "dex-operator"
	svc.ObjectMeta.Labels["app.kubernetes.io/instance"] = idp.Name
	svc.ObjectMeta.Labels["app.kubernetes.io/managed-by"] = "dex-operator"
	svc.ObjectMeta.Labels["app.kubernetes.io/component"] = "metrics"

	return &svc, nil
}

func (r *DexIdentityProviderReconciler) serviceMonitorTemplate(idp *dexv1alpha1.DexIdentityProvider) (*monitoringv1.ServiceMonitor, error) {
	svcMonitor := monitoringv1.ServiceMonitor{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("dex-%s", idp.Name),
			Namespace: idp.Namespace,
			Labels:    make(map[string]string),
		},
		Spec: monitoringv1.ServiceMonitorSpec{
			Selector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app.kubernetes.io/name":      "dex",
					"app.kubernetes.io/instance":  idp.Name,
					"app.kubernetes.io/component": "metrics",
				},
			},
			Endpoints: []monitoringv1.Endpoint{{
				Port:     "metrics",
				Interval: monitoringv1.Duration(idp.Spec.Metrics.Interval),
			}},
		},
	}

	if err := controllerutil.SetControllerReference(idp, &svcMonitor, r.Scheme); err != nil {
		return nil, fmt.Errorf("failed to set controller reference: %w", err)
	}

	for k, v := range idp.ObjectMeta.Labels {
		svcMonitor.ObjectMeta.Labels[k] = v
	}

	svcMonitor.ObjectMeta.Labels["app.kubernetes.io/name"] = "dex"
	svcMonitor.ObjectMeta.Labels["app.kubernetes.io/instance"] = idp.Name
	svcMonitor.ObjectMeta.Labels["app.kubernetes.io/managed-by"] = "dex-operator"
	svcMonitor.ObjectMeta.Labels["app.kubernetes.io/component"] = "metrics"

	return &svcMonitor, nil
}

func (r *DexIdentityProviderReconciler) configSecretTemplate(ctx context.Context, idp *dexv1alpha1.DexIdentityProvider) (*corev1.Secret, error) {
	config, err := dex.ConfigFromCR(ctx, r.Client, r.Scheme, idp)
	if err != nil {
		return nil, fmt.Errorf("failed to generate dex config: %w", err)
	}

	configYAML, err := yaml.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal dex config: %w", err)
	}

	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("dex-%s-config", idp.Name),
			Namespace: idp.Namespace,
			Labels:    make(map[string]string),
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"config.yaml": []byte(configYAML),
		},
	}

	if err := controllerutil.SetControllerReference(idp, &secret, r.Scheme); err != nil {
		return nil, fmt.Errorf("failed to set controller reference: %w", err)
	}

	for k, v := range idp.ObjectMeta.Labels {
		secret.ObjectMeta.Labels[k] = v
	}

	secret.ObjectMeta.Labels["app.kubernetes.io/name"] = "dex"
	secret.ObjectMeta.Labels["app.kubernetes.io/instance"] = idp.Name
	secret.ObjectMeta.Labels["app.kubernetes.io/managed-by"] = "dex-operator"

	// Give each revision of the configmap a unique name so that dependent pods are
	// recreated when the config changes.
	secret.ObjectMeta.Name += "-" + updater.HashObject(&secret)

	return &secret, nil
}

func getDexCertificateVolumes(idp *dexv1alpha1.DexIdentityProvider) ([]corev1.Volume, []corev1.VolumeMount, error) {
	type referencedSecret struct {
		secretName string
		caOnly     bool
	}
	referencedSecrets := map[string]*referencedSecret{}

	addReferencedSecret := func(secretName string, caOnly bool) {
		if existing, ok := referencedSecrets[secretName]; ok {
			if existing.caOnly && !caOnly {
				existing.caOnly = false
			}
		} else {
			referencedSecrets[secretName] = &referencedSecret{
				secretName: secretName,
				caOnly:     caOnly,
			}
		}
	}

	if idp.Spec.Web.CertificateSecretRef != nil {
		addReferencedSecret(idp.Spec.Web.CertificateSecretRef.Name, false)
	}

	if idp.Spec.GRPC.CertificateSecretRef != nil {
		addReferencedSecret(idp.Spec.GRPC.CertificateSecretRef.Name, false)
	}

	if idp.Spec.GRPC.ClientCASecretRef != nil {
		addReferencedSecret(idp.Spec.GRPC.ClientCASecretRef.Name, true)
	}

	if idp.Spec.Storage.Type == dexv1alpha1.DexIdentityProviderStorageTypePostgres &&
		idp.Spec.Storage.Postgres != nil &&
		idp.Spec.Storage.Postgres.SSL != nil {
		if idp.Spec.Storage.Postgres.SSL.CASecretRef != nil {
			addReferencedSecret(idp.Spec.Storage.Postgres.SSL.CASecretRef.Name, true)
		}

		if idp.Spec.Storage.Postgres.SSL.ClientCertificateSecretRef != nil {
			addReferencedSecret(idp.Spec.Storage.Postgres.SSL.ClientCertificateSecretRef.Name, false)
		}
	}

	for _, connector := range idp.Spec.Connectors {
		if connector.Type == dexv1alpha1.DexIdentityProviderConnectorTypeLDAP && connector.LDAP != nil {
			if connector.LDAP.CASecretRef != nil {
				addReferencedSecret(connector.LDAP.CASecretRef.Name, true)
			}

			if connector.LDAP.ClientCertificateSecretRef != nil {
				addReferencedSecret(connector.LDAP.ClientCertificateSecretRef.Name, false)
			}
		} else if connector.Type == dexv1alpha1.DexIdentityProviderConnectorTypeOIDC && connector.OIDC != nil {
			if connector.OIDC.CASecretRef != nil {
				addReferencedSecret(connector.OIDC.CASecretRef.Name, true)
			}
		}
	}

	var volumes []corev1.Volume
	var volumeMounts []corev1.VolumeMount

	for _, referencedSecret := range referencedSecrets {
		volumes = append(volumes, corev1.Volume{
			Name: referencedSecret.secretName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: referencedSecret.secretName,
				},
			},
		})

		volumeMount := corev1.VolumeMount{
			Name:      referencedSecret.secretName,
			MountPath: filepath.Join(dex.CertsBase, referencedSecret.secretName),
			ReadOnly:  true,
		}
		if referencedSecret.caOnly {
			volumeMount.MountPath = filepath.Join(volumeMount.MountPath, "ca.crt")
			volumeMount.SubPath = "ca.crt"
		}

		volumeMounts = append(volumeMounts, volumeMount)
	}

	sort.Slice(volumes, func(i, j int) bool {
		return volumes[i].Name < volumes[j].Name
	})

	sort.Slice(volumeMounts, func(i, j int) bool {
		return volumeMounts[i].Name < volumeMounts[j].Name
	})

	return volumes, volumeMounts, nil
}

func getDexPorts(idp *dexv1alpha1.DexIdentityProvider) ([]corev1.ContainerPort, error) {
	ports := []corev1.ContainerPort{
		{
			Name:          "grpc",
			ContainerPort: 8081,
			Protocol:      corev1.ProtocolTCP,
		},
		{
			Name:          "metrics",
			ContainerPort: 9090,
			Protocol:      corev1.ProtocolTCP,
		},
	}

	if idp.Spec.Web.CertificateSecretRef != nil {
		ports = append(ports, corev1.ContainerPort{
			Name:          "https",
			ContainerPort: 8443,
			Protocol:      corev1.ProtocolTCP,
		})
	} else {
		ports = append(ports, corev1.ContainerPort{
			Name:          "http",
			ContainerPort: 8080,
			Protocol:      corev1.ProtocolTCP,
		})
	}

	return ports, nil
}
