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

	"github.com/dexidp/dex/api/v2"
	dexv1alpha1 "github.com/gpu-ninja/dex-operator/api/v1alpha1"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type fakeClientBuilder struct {
	m *mock.Mock
}

func NewFakeClientBuilder(m *mock.Mock) ClientBuilder {
	return &fakeClientBuilder{
		m: m,
	}
}

func (b *fakeClientBuilder) WithReader(reader client.Reader) ClientBuilder {
	return &fakeClientBuilder{
		m: b.m,
	}
}

func (b *fakeClientBuilder) WithScheme(scheme *runtime.Scheme) ClientBuilder {
	return &fakeClientBuilder{
		m: b.m,
	}
}

func (b *fakeClientBuilder) WithIdentityProvider(idp *dexv1alpha1.DexIdentityProvider) ClientBuilder {
	return &fakeClientBuilder{
		m: b.m,
	}
}

func (b *fakeClientBuilder) Build(ctx context.Context) (api.DexClient, error) {
	return &FakeDexClient{
		Mock: b.m,
	}, nil
}

type FakeDexClient struct {
	*mock.Mock
}

// CreateClient creates a client.
func (c *FakeDexClient) CreateClient(ctx context.Context, in *api.CreateClientReq, opts ...grpc.CallOption) (*api.CreateClientResp, error) {
	args := c.Called(ctx, in, opts)
	return args.Get(0).(*api.CreateClientResp), args.Error(1)
}

// UpdateClient updates an existing client
func (c *FakeDexClient) UpdateClient(ctx context.Context, in *api.UpdateClientReq, opts ...grpc.CallOption) (*api.UpdateClientResp, error) {
	args := c.Called(ctx, in, opts)
	return args.Get(0).(*api.UpdateClientResp), args.Error(1)
}

// DeleteClient deletes the provided client.
func (c *FakeDexClient) DeleteClient(ctx context.Context, in *api.DeleteClientReq, opts ...grpc.CallOption) (*api.DeleteClientResp, error) {
	args := c.Called(ctx, in, opts)
	return args.Get(0).(*api.DeleteClientResp), args.Error(1)
}

// CreatePassword creates a password.
func (c *FakeDexClient) CreatePassword(ctx context.Context, in *api.CreatePasswordReq, opts ...grpc.CallOption) (*api.CreatePasswordResp, error) {
	args := c.Called(ctx, in, opts)
	return args.Get(0).(*api.CreatePasswordResp), args.Error(1)
}

// UpdatePassword modifies existing password.
func (c *FakeDexClient) UpdatePassword(ctx context.Context, in *api.UpdatePasswordReq, opts ...grpc.CallOption) (*api.UpdatePasswordResp, error) {
	args := c.Called(ctx, in, opts)
	return args.Get(0).(*api.UpdatePasswordResp), args.Error(1)
}

// DeletePassword deletes the password.
func (c *FakeDexClient) DeletePassword(ctx context.Context, in *api.DeletePasswordReq, opts ...grpc.CallOption) (*api.DeletePasswordResp, error) {
	args := c.Called(ctx, in, opts)
	return args.Get(0).(*api.DeletePasswordResp), args.Error(1)
}

// ListPassword lists all password entries.
func (c *FakeDexClient) ListPasswords(ctx context.Context, in *api.ListPasswordReq, opts ...grpc.CallOption) (*api.ListPasswordResp, error) {
	args := c.Called(ctx, in, opts)
	return args.Get(0).(*api.ListPasswordResp), args.Error(1)
}

// GetVersion returns version information of the server.
func (c *FakeDexClient) GetVersion(ctx context.Context, in *api.VersionReq, opts ...grpc.CallOption) (*api.VersionResp, error) {
	args := c.Called(ctx, in, opts)
	return args.Get(0).(*api.VersionResp), args.Error(1)
}

// ListRefresh lists all the refresh token entries for a particular user.
func (c *FakeDexClient) ListRefresh(ctx context.Context, in *api.ListRefreshReq, opts ...grpc.CallOption) (*api.ListRefreshResp, error) {
	args := c.Called(ctx, in, opts)
	return args.Get(0).(*api.ListRefreshResp), args.Error(1)
}

// RevokeRefresh revokes the refresh token for the provided user-client pair.
//
// Note that each user-client pair can have only one refresh token at a time.
func (c *FakeDexClient) RevokeRefresh(ctx context.Context, in *api.RevokeRefreshReq, opts ...grpc.CallOption) (*api.RevokeRefreshResp, error) {
	args := c.Called(ctx, in, opts)
	return args.Get(0).(*api.RevokeRefreshResp), args.Error(1)
}

// VerifyPassword returns whether a password matches a hash for a specific email or not.
func (c *FakeDexClient) VerifyPassword(ctx context.Context, in *api.VerifyPasswordReq, opts ...grpc.CallOption) (*api.VerifyPasswordResp, error) {
	args := c.Called(ctx, in, opts)
	return args.Get(0).(*api.VerifyPasswordResp), args.Error(1)
}
