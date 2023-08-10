//go:build !ignore_autogenerated
// +build !ignore_autogenerated

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

// Code generated by controller-gen. DO NOT EDIT.

package v1alpha1

import (
	"github.com/gpu-ninja/operator-utils/reference"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DexIdentityProvider) DeepCopyInto(out *DexIdentityProvider) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DexIdentityProvider.
func (in *DexIdentityProvider) DeepCopy() *DexIdentityProvider {
	if in == nil {
		return nil
	}
	out := new(DexIdentityProvider)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *DexIdentityProvider) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DexIdentityProviderConnectorLDAPGroupSearchSpec) DeepCopyInto(out *DexIdentityProviderConnectorLDAPGroupSearchSpec) {
	*out = *in
	if in.UserMatchers != nil {
		in, out := &in.UserMatchers, &out.UserMatchers
		*out = make([]DexIdentityProviderConnectorLDAPGroupSearchUserMatcher, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DexIdentityProviderConnectorLDAPGroupSearchSpec.
func (in *DexIdentityProviderConnectorLDAPGroupSearchSpec) DeepCopy() *DexIdentityProviderConnectorLDAPGroupSearchSpec {
	if in == nil {
		return nil
	}
	out := new(DexIdentityProviderConnectorLDAPGroupSearchSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DexIdentityProviderConnectorLDAPGroupSearchUserMatcher) DeepCopyInto(out *DexIdentityProviderConnectorLDAPGroupSearchUserMatcher) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DexIdentityProviderConnectorLDAPGroupSearchUserMatcher.
func (in *DexIdentityProviderConnectorLDAPGroupSearchUserMatcher) DeepCopy() *DexIdentityProviderConnectorLDAPGroupSearchUserMatcher {
	if in == nil {
		return nil
	}
	out := new(DexIdentityProviderConnectorLDAPGroupSearchUserMatcher)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DexIdentityProviderConnectorLDAPSpec) DeepCopyInto(out *DexIdentityProviderConnectorLDAPSpec) {
	*out = *in
	if in.CASecretRef != nil {
		in, out := &in.CASecretRef, &out.CASecretRef
		*out = new(reference.LocalSecretReference)
		**out = **in
	}
	if in.ClientCertificateSecretRef != nil {
		in, out := &in.ClientCertificateSecretRef, &out.ClientCertificateSecretRef
		*out = new(reference.LocalSecretReference)
		**out = **in
	}
	out.BindCredentialsSecretRef = in.BindCredentialsSecretRef
	out.UserSearch = in.UserSearch
	in.GroupSearch.DeepCopyInto(&out.GroupSearch)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DexIdentityProviderConnectorLDAPSpec.
func (in *DexIdentityProviderConnectorLDAPSpec) DeepCopy() *DexIdentityProviderConnectorLDAPSpec {
	if in == nil {
		return nil
	}
	out := new(DexIdentityProviderConnectorLDAPSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DexIdentityProviderConnectorLDAPUserSearchSpec) DeepCopyInto(out *DexIdentityProviderConnectorLDAPUserSearchSpec) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DexIdentityProviderConnectorLDAPUserSearchSpec.
func (in *DexIdentityProviderConnectorLDAPUserSearchSpec) DeepCopy() *DexIdentityProviderConnectorLDAPUserSearchSpec {
	if in == nil {
		return nil
	}
	out := new(DexIdentityProviderConnectorLDAPUserSearchSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DexIdentityProviderConnectorOIDCClaimMapping) DeepCopyInto(out *DexIdentityProviderConnectorOIDCClaimMapping) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DexIdentityProviderConnectorOIDCClaimMapping.
func (in *DexIdentityProviderConnectorOIDCClaimMapping) DeepCopy() *DexIdentityProviderConnectorOIDCClaimMapping {
	if in == nil {
		return nil
	}
	out := new(DexIdentityProviderConnectorOIDCClaimMapping)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DexIdentityProviderConnectorOIDCSpec) DeepCopyInto(out *DexIdentityProviderConnectorOIDCSpec) {
	*out = *in
	out.ClientSecretRef = in.ClientSecretRef
	if in.BasicAuthUnsupported != nil {
		in, out := &in.BasicAuthUnsupported, &out.BasicAuthUnsupported
		*out = new(bool)
		**out = **in
	}
	if in.Scopes != nil {
		in, out := &in.Scopes, &out.Scopes
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.CASecretRef != nil {
		in, out := &in.CASecretRef, &out.CASecretRef
		*out = new(reference.LocalSecretReference)
		**out = **in
	}
	if in.AcrValues != nil {
		in, out := &in.AcrValues, &out.AcrValues
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.ClaimMapping != nil {
		in, out := &in.ClaimMapping, &out.ClaimMapping
		*out = new(DexIdentityProviderConnectorOIDCClaimMapping)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DexIdentityProviderConnectorOIDCSpec.
func (in *DexIdentityProviderConnectorOIDCSpec) DeepCopy() *DexIdentityProviderConnectorOIDCSpec {
	if in == nil {
		return nil
	}
	out := new(DexIdentityProviderConnectorOIDCSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DexIdentityProviderConnectorSpec) DeepCopyInto(out *DexIdentityProviderConnectorSpec) {
	*out = *in
	if in.LDAP != nil {
		in, out := &in.LDAP, &out.LDAP
		*out = new(DexIdentityProviderConnectorLDAPSpec)
		(*in).DeepCopyInto(*out)
	}
	if in.OIDC != nil {
		in, out := &in.OIDC, &out.OIDC
		*out = new(DexIdentityProviderConnectorOIDCSpec)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DexIdentityProviderConnectorSpec.
func (in *DexIdentityProviderConnectorSpec) DeepCopy() *DexIdentityProviderConnectorSpec {
	if in == nil {
		return nil
	}
	out := new(DexIdentityProviderConnectorSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DexIdentityProviderExpirySpec) DeepCopyInto(out *DexIdentityProviderExpirySpec) {
	*out = *in
	if in.SigningKeys != nil {
		in, out := &in.SigningKeys, &out.SigningKeys
		*out = new(v1.Duration)
		**out = **in
	}
	if in.IDTokens != nil {
		in, out := &in.IDTokens, &out.IDTokens
		*out = new(v1.Duration)
		**out = **in
	}
	if in.AuthRequests != nil {
		in, out := &in.AuthRequests, &out.AuthRequests
		*out = new(v1.Duration)
		**out = **in
	}
	if in.DeviceRequests != nil {
		in, out := &in.DeviceRequests, &out.DeviceRequests
		*out = new(v1.Duration)
		**out = **in
	}
	if in.RefreshTokens != nil {
		in, out := &in.RefreshTokens, &out.RefreshTokens
		*out = new(DexIdentityProviderRefreshTokenSpec)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DexIdentityProviderExpirySpec.
func (in *DexIdentityProviderExpirySpec) DeepCopy() *DexIdentityProviderExpirySpec {
	if in == nil {
		return nil
	}
	out := new(DexIdentityProviderExpirySpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DexIdentityProviderFrontendSpec) DeepCopyInto(out *DexIdentityProviderFrontendSpec) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DexIdentityProviderFrontendSpec.
func (in *DexIdentityProviderFrontendSpec) DeepCopy() *DexIdentityProviderFrontendSpec {
	if in == nil {
		return nil
	}
	out := new(DexIdentityProviderFrontendSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DexIdentityProviderGRPCSpec) DeepCopyInto(out *DexIdentityProviderGRPCSpec) {
	*out = *in
	if in.CertificateSecretRef != nil {
		in, out := &in.CertificateSecretRef, &out.CertificateSecretRef
		*out = new(reference.LocalSecretReference)
		**out = **in
	}
	if in.ClientCASecretRef != nil {
		in, out := &in.ClientCASecretRef, &out.ClientCASecretRef
		*out = new(reference.LocalSecretReference)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DexIdentityProviderGRPCSpec.
func (in *DexIdentityProviderGRPCSpec) DeepCopy() *DexIdentityProviderGRPCSpec {
	if in == nil {
		return nil
	}
	out := new(DexIdentityProviderGRPCSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DexIdentityProviderList) DeepCopyInto(out *DexIdentityProviderList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]DexIdentityProvider, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DexIdentityProviderList.
func (in *DexIdentityProviderList) DeepCopy() *DexIdentityProviderList {
	if in == nil {
		return nil
	}
	out := new(DexIdentityProviderList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *DexIdentityProviderList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DexIdentityProviderLocalStorageSpec) DeepCopyInto(out *DexIdentityProviderLocalStorageSpec) {
	*out = *in
	if in.StorageClassName != nil {
		in, out := &in.StorageClassName, &out.StorageClassName
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DexIdentityProviderLocalStorageSpec.
func (in *DexIdentityProviderLocalStorageSpec) DeepCopy() *DexIdentityProviderLocalStorageSpec {
	if in == nil {
		return nil
	}
	out := new(DexIdentityProviderLocalStorageSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DexIdentityProviderLoggerSpec) DeepCopyInto(out *DexIdentityProviderLoggerSpec) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DexIdentityProviderLoggerSpec.
func (in *DexIdentityProviderLoggerSpec) DeepCopy() *DexIdentityProviderLoggerSpec {
	if in == nil {
		return nil
	}
	out := new(DexIdentityProviderLoggerSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DexIdentityProviderOAuth2Spec) DeepCopyInto(out *DexIdentityProviderOAuth2Spec) {
	*out = *in
	if in.GrantTypes != nil {
		in, out := &in.GrantTypes, &out.GrantTypes
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.ResponseTypes != nil {
		in, out := &in.ResponseTypes, &out.ResponseTypes
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DexIdentityProviderOAuth2Spec.
func (in *DexIdentityProviderOAuth2Spec) DeepCopy() *DexIdentityProviderOAuth2Spec {
	if in == nil {
		return nil
	}
	out := new(DexIdentityProviderOAuth2Spec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DexIdentityProviderRefreshTokenSpec) DeepCopyInto(out *DexIdentityProviderRefreshTokenSpec) {
	*out = *in
	if in.ReuseInterval != nil {
		in, out := &in.ReuseInterval, &out.ReuseInterval
		*out = new(v1.Duration)
		**out = **in
	}
	if in.AbsoluteLifetime != nil {
		in, out := &in.AbsoluteLifetime, &out.AbsoluteLifetime
		*out = new(v1.Duration)
		**out = **in
	}
	if in.ValidIfNotUsedFor != nil {
		in, out := &in.ValidIfNotUsedFor, &out.ValidIfNotUsedFor
		*out = new(v1.Duration)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DexIdentityProviderRefreshTokenSpec.
func (in *DexIdentityProviderRefreshTokenSpec) DeepCopy() *DexIdentityProviderRefreshTokenSpec {
	if in == nil {
		return nil
	}
	out := new(DexIdentityProviderRefreshTokenSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DexIdentityProviderSpec) DeepCopyInto(out *DexIdentityProviderSpec) {
	*out = *in
	if in.Replicas != nil {
		in, out := &in.Replicas, &out.Replicas
		*out = new(int32)
		**out = **in
	}
	if in.ClientCertificateSecretRef != nil {
		in, out := &in.ClientCertificateSecretRef, &out.ClientCertificateSecretRef
		*out = new(reference.LocalSecretReference)
		**out = **in
	}
	in.Storage.DeepCopyInto(&out.Storage)
	in.Web.DeepCopyInto(&out.Web)
	in.GRPC.DeepCopyInto(&out.GRPC)
	if in.OAuth2 != nil {
		in, out := &in.OAuth2, &out.OAuth2
		*out = new(DexIdentityProviderOAuth2Spec)
		(*in).DeepCopyInto(*out)
	}
	if in.Expiry != nil {
		in, out := &in.Expiry, &out.Expiry
		*out = new(DexIdentityProviderExpirySpec)
		(*in).DeepCopyInto(*out)
	}
	if in.Frontend != nil {
		in, out := &in.Frontend, &out.Frontend
		*out = new(DexIdentityProviderFrontendSpec)
		**out = **in
	}
	if in.Logger != nil {
		in, out := &in.Logger, &out.Logger
		*out = new(DexIdentityProviderLoggerSpec)
		**out = **in
	}
	if in.Connectors != nil {
		in, out := &in.Connectors, &out.Connectors
		*out = make([]DexIdentityProviderConnectorSpec, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.LocalStorage != nil {
		in, out := &in.LocalStorage, &out.LocalStorage
		*out = new(DexIdentityProviderLocalStorageSpec)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DexIdentityProviderSpec.
func (in *DexIdentityProviderSpec) DeepCopy() *DexIdentityProviderSpec {
	if in == nil {
		return nil
	}
	out := new(DexIdentityProviderSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DexIdentityProviderStatus) DeepCopyInto(out *DexIdentityProviderStatus) {
	*out = *in
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]v1.Condition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DexIdentityProviderStatus.
func (in *DexIdentityProviderStatus) DeepCopy() *DexIdentityProviderStatus {
	if in == nil {
		return nil
	}
	out := new(DexIdentityProviderStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DexIdentityProviderStorageNetworkDBSpec) DeepCopyInto(out *DexIdentityProviderStorageNetworkDBSpec) {
	*out = *in
	out.CredentialsSecretRef = in.CredentialsSecretRef
	if in.ConnectionTimeout != nil {
		in, out := &in.ConnectionTimeout, &out.ConnectionTimeout
		*out = new(v1.Duration)
		**out = **in
	}
	if in.MaxOpenConns != nil {
		in, out := &in.MaxOpenConns, &out.MaxOpenConns
		*out = new(int)
		**out = **in
	}
	if in.MaxIdleConns != nil {
		in, out := &in.MaxIdleConns, &out.MaxIdleConns
		*out = new(int)
		**out = **in
	}
	if in.ConnMaxLifetime != nil {
		in, out := &in.ConnMaxLifetime, &out.ConnMaxLifetime
		*out = new(v1.Duration)
		**out = **in
	}
	if in.SSL != nil {
		in, out := &in.SSL, &out.SSL
		*out = new(DexIdentityProviderStorageSSLSpec)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DexIdentityProviderStorageNetworkDBSpec.
func (in *DexIdentityProviderStorageNetworkDBSpec) DeepCopy() *DexIdentityProviderStorageNetworkDBSpec {
	if in == nil {
		return nil
	}
	out := new(DexIdentityProviderStorageNetworkDBSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DexIdentityProviderStorageSSLSpec) DeepCopyInto(out *DexIdentityProviderStorageSSLSpec) {
	*out = *in
	if in.CASecretRef != nil {
		in, out := &in.CASecretRef, &out.CASecretRef
		*out = new(reference.LocalSecretReference)
		**out = **in
	}
	if in.ClientCertificateSecretRef != nil {
		in, out := &in.ClientCertificateSecretRef, &out.ClientCertificateSecretRef
		*out = new(reference.LocalSecretReference)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DexIdentityProviderStorageSSLSpec.
func (in *DexIdentityProviderStorageSSLSpec) DeepCopy() *DexIdentityProviderStorageSSLSpec {
	if in == nil {
		return nil
	}
	out := new(DexIdentityProviderStorageSSLSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DexIdentityProviderStorageSpec) DeepCopyInto(out *DexIdentityProviderStorageSpec) {
	*out = *in
	if in.Sqlite3 != nil {
		in, out := &in.Sqlite3, &out.Sqlite3
		*out = new(DexIdentityProviderStorageSqlite3Spec)
		**out = **in
	}
	if in.Postgres != nil {
		in, out := &in.Postgres, &out.Postgres
		*out = new(DexIdentityProviderStorageNetworkDBSpec)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DexIdentityProviderStorageSpec.
func (in *DexIdentityProviderStorageSpec) DeepCopy() *DexIdentityProviderStorageSpec {
	if in == nil {
		return nil
	}
	out := new(DexIdentityProviderStorageSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DexIdentityProviderStorageSqlite3Spec) DeepCopyInto(out *DexIdentityProviderStorageSqlite3Spec) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DexIdentityProviderStorageSqlite3Spec.
func (in *DexIdentityProviderStorageSqlite3Spec) DeepCopy() *DexIdentityProviderStorageSqlite3Spec {
	if in == nil {
		return nil
	}
	out := new(DexIdentityProviderStorageSqlite3Spec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DexIdentityProviderWebSpec) DeepCopyInto(out *DexIdentityProviderWebSpec) {
	*out = *in
	if in.CertificateSecretRef != nil {
		in, out := &in.CertificateSecretRef, &out.CertificateSecretRef
		*out = new(reference.LocalSecretReference)
		**out = **in
	}
	if in.AllowedOrigins != nil {
		in, out := &in.AllowedOrigins, &out.AllowedOrigins
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DexIdentityProviderWebSpec.
func (in *DexIdentityProviderWebSpec) DeepCopy() *DexIdentityProviderWebSpec {
	if in == nil {
		return nil
	}
	out := new(DexIdentityProviderWebSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DexOAuth2Client) DeepCopyInto(out *DexOAuth2Client) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	out.Status = in.Status
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DexOAuth2Client.
func (in *DexOAuth2Client) DeepCopy() *DexOAuth2Client {
	if in == nil {
		return nil
	}
	out := new(DexOAuth2Client)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *DexOAuth2Client) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DexOAuth2ClientList) DeepCopyInto(out *DexOAuth2ClientList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]DexOAuth2Client, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DexOAuth2ClientList.
func (in *DexOAuth2ClientList) DeepCopy() *DexOAuth2ClientList {
	if in == nil {
		return nil
	}
	out := new(DexOAuth2ClientList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *DexOAuth2ClientList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DexOAuth2ClientSpec) DeepCopyInto(out *DexOAuth2ClientSpec) {
	*out = *in
	out.IdentityProviderRef = in.IdentityProviderRef
	if in.RedirectURIs != nil {
		in, out := &in.RedirectURIs, &out.RedirectURIs
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.TrustedPeers != nil {
		in, out := &in.TrustedPeers, &out.TrustedPeers
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DexOAuth2ClientSpec.
func (in *DexOAuth2ClientSpec) DeepCopy() *DexOAuth2ClientSpec {
	if in == nil {
		return nil
	}
	out := new(DexOAuth2ClientSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DexOAuth2ClientStatus) DeepCopyInto(out *DexOAuth2ClientStatus) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DexOAuth2ClientStatus.
func (in *DexOAuth2ClientStatus) DeepCopy() *DexOAuth2ClientStatus {
	if in == nil {
		return nil
	}
	out := new(DexOAuth2ClientStatus)
	in.DeepCopyInto(out)
	return out
}
