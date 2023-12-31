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

package api

import ()

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DexIdentityProviderReference) DeepCopyInto(out *DexIdentityProviderReference) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DexIdentityProviderReference.
func (in *DexIdentityProviderReference) DeepCopy() *DexIdentityProviderReference {
	if in == nil {
		return nil
	}
	out := new(DexIdentityProviderReference)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DexOAuth2ClientReference) DeepCopyInto(out *DexOAuth2ClientReference) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DexOAuth2ClientReference.
func (in *DexOAuth2ClientReference) DeepCopy() *DexOAuth2ClientReference {
	if in == nil {
		return nil
	}
	out := new(DexOAuth2ClientReference)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *LocalDexIdentityProviderReference) DeepCopyInto(out *LocalDexIdentityProviderReference) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new LocalDexIdentityProviderReference.
func (in *LocalDexIdentityProviderReference) DeepCopy() *LocalDexIdentityProviderReference {
	if in == nil {
		return nil
	}
	out := new(LocalDexIdentityProviderReference)
	in.DeepCopyInto(out)
	return out
}
