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

package main_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func TestOperator(t *testing.T) {
	t.Log("Creating example resources")

	rootDir := os.Getenv("ROOT_DIR")

	require.NoError(t, createExampleResources(filepath.Join(rootDir, "examples")))

	kubeconfig := filepath.Join(clientcmd.RecommendedConfigDir, "config")
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	require.NoError(t, err)

	clientset, err := kubernetes.NewForConfig(config)
	require.NoError(t, err)

	t.Log("Waiting for demo-client-secret to be created")

	ctx := context.Background()
	err = wait.PollUntilContextTimeout(ctx, 5*time.Second, 5*time.Minute, true, func(ctx context.Context) (bool, error) {
		_, err := clientset.CoreV1().Secrets("default").Get(ctx, "demo-client-secret", metav1.GetOptions{})
		if err != nil {
			if !apierrors.IsNotFound(err) {
				return true, err
			}

			t.Log("Not yet ready")

			return false, nil
		}

		return true, nil
	})
	require.NoError(t, err, "failed to wait for demo-client-secret")

	t.Log("Waiting for demo user to be ready")

	dynamicClient, err := dynamic.NewForConfig(config)
	require.NoError(t, err)

	gvr := schema.GroupVersionResource{
		Group:    "dex.gpu-ninja.com",
		Version:  "v1alpha1",
		Resource: "dexusers",
	}

	err = wait.PollUntilContextTimeout(ctx, 5*time.Second, 5*time.Minute, true, func(ctx context.Context) (bool, error) {
		user, err := dynamicClient.Resource(gvr).Namespace("default").Get(ctx, "demo", metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		phase, found, err := unstructured.NestedString(user.Object, "status", "phase")
		if err != nil {
			return false, err
		}

		if !found || phase != "Ready" {
			t.Log("Not yet ready")

			return false, nil
		} else {
			return true, nil
		}
	})
	require.NoError(t, err, "failed to wait for demo user to be ready")

	t.Log("Checking demo-user-password secret has been created")

	_, err = clientset.CoreV1().Secrets("default").Get(ctx, "demo-user-password", metav1.GetOptions{})
	require.NoError(t, err, "failed to get demo-user-password secret")

	t.Log("Deleting dex identity provider (to test cleanup)")

	gvr = schema.GroupVersionResource{
		Group:    "dex.gpu-ninja.com",
		Version:  "v1alpha1",
		Resource: "dexidentityproviders",
	}

	err = dynamicClient.Resource(gvr).Namespace("default").Delete(ctx, "demo", metav1.DeleteOptions{})
	require.NoError(t, err)

	t.Log("Waiting for demo-client-secret to be deleted")

	err = wait.PollUntilContextTimeout(ctx, 5*time.Second, 5*time.Minute, true, func(ctx context.Context) (bool, error) {
		_, err := clientset.CoreV1().Secrets("default").Get(ctx, "demo-client-secret", metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return true, nil
		} else if err != nil {
			return true, err
		}

		t.Log("Not yet deleted")

		return false, nil
	})
	require.NoError(t, err, "failed to wait for demo-client-secret to be deleted")

	t.Log("Waiting for demo-user-password to be deleted")

	err = wait.PollUntilContextTimeout(ctx, 5*time.Second, 5*time.Minute, true, func(ctx context.Context) (bool, error) {
		_, err := clientset.CoreV1().Secrets("default").Get(ctx, "demo-user-password", metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return true, nil
		} else if err != nil {
			return true, err
		}

		t.Log("Not yet deleted")

		return false, nil
	})
	require.NoError(t, err, "failed to wait for demo-user-password to be deleted")

	t.Log("Deleting example resources")

	require.NoError(t, deleteExampleResources())
}

func createExampleResources(examplesDir string) error {
	cmd := exec.Command("kapp", "deploy", "-y", "-a", "dex-operator-examples", "-f", examplesDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

func deleteExampleResources() error {
	cmd := exec.Command("kapp", "delete", "-y", "-a", "dex-operator-examples")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}
