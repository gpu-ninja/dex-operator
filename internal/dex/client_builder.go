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

package dex

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/dexidp/dex/api/v2"
	dexv1alpha1 "github.com/gpu-ninja/dex-operator/api/v1alpha1"
	"github.com/gpu-ninja/operator-utils/k8sutils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type ClientBuilder interface {
	WithReader(reader client.Reader) ClientBuilder
	WithScheme(scheme *runtime.Scheme) ClientBuilder
	WithIdentityProvider(idp *dexv1alpha1.DexIdentityProvider) ClientBuilder
	Build(ctx context.Context) (api.DexClient, error)
}

type clientBuilderImpl struct {
	reader client.Reader
	scheme *runtime.Scheme
	idp    *dexv1alpha1.DexIdentityProvider
}

func NewClientBuilder() ClientBuilder {
	return &clientBuilderImpl{}
}

func (b *clientBuilderImpl) WithReader(reader client.Reader) ClientBuilder {
	return &clientBuilderImpl{
		reader: reader,
		scheme: b.scheme,
		idp:    b.idp,
	}
}

func (b *clientBuilderImpl) WithScheme(scheme *runtime.Scheme) ClientBuilder {
	return &clientBuilderImpl{
		reader: b.reader,
		scheme: scheme,
		idp:    b.idp,
	}
}

func (b *clientBuilderImpl) WithIdentityProvider(idp *dexv1alpha1.DexIdentityProvider) ClientBuilder {
	return &clientBuilderImpl{
		reader: b.reader,
		scheme: b.scheme,
		idp:    idp,
	}
}

func (b *clientBuilderImpl) Build(ctx context.Context) (api.DexClient, error) {
	hostAndPort := fmt.Sprintf("%s-api.%s.svc.%s:443", b.idp.Name, b.idp.Namespace, k8sutils.GetClusterDomain())

	transportCredentials := insecure.NewCredentials()
	if b.idp.Spec.GRPC.CertificateSecretRef != nil {
		certificateSecret, err := b.idp.Spec.GRPC.CertificateSecretRef.Resolve(ctx, b.reader, b.scheme, b.idp)
		if err != nil {
			return nil, fmt.Errorf("failed to get grpc certificate secret: %w", err)
		}

		rootCAs := x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM(certificateSecret.(*corev1.Secret).Data["ca.crt"]) {
			return nil, fmt.Errorf("failed to append ca certificate to root CAs")
		}

		clientTLSConfig := &tls.Config{
			RootCAs: rootCAs,
		}

		if b.idp.Spec.ClientCertificateSecretRef != nil {
			clientCertificateSecret, err := b.idp.Spec.ClientCertificateSecretRef.Resolve(ctx, b.reader, b.scheme, b.idp)
			if err != nil {
				return nil, fmt.Errorf("failed to get grpc client certificate secret: %w", err)
			}

			clientCert, err := tls.X509KeyPair(clientCertificateSecret.(*corev1.Secret).Data["tls.crt"], clientCertificateSecret.(*corev1.Secret).Data["tls.key"])
			if err != nil {
				return nil, fmt.Errorf("failed to parse grpc client certificate: %w", err)
			}

			clientTLSConfig.Certificates = []tls.Certificate{clientCert}
		}

		transportCredentials = credentials.NewTLS(clientTLSConfig)
	}

	conn, err := grpc.Dial(hostAndPort, grpc.WithTransportCredentials(transportCredentials))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to dex: %w", err)
	}

	return api.NewDexClient(conn), nil
}
