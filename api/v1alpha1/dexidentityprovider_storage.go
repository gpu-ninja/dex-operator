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

package v1alpha1

import (
	"github.com/gpu-ninja/operator-utils/reference"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// DexIdentityProviderStorageType defines the storage type to use.
// We only support a subset of the available Dex storage types atm.
type DexIdentityProviderStorageType string

const (
	DexIdentityProviderStorageTypeMemory   DexIdentityProviderStorageType = "memory"
	DexIdentityProviderStorageTypeSqlite3  DexIdentityProviderStorageType = "sqlite3"
	DexIdentityProviderStorageTypePostgres DexIdentityProviderStorageType = "postgres"
)

// DexIdentityProviderStorageSqlite3Spec holds configuration for sqlite3 storage.
type DexIdentityProviderStorageSqlite3Spec struct {
	// File is the path to the sqlite3 database file.
	File string `json:"file"`
}

// SSL represents SSL options for etcd databases.
type DexIdentityProviderStorageSSLSpec struct {
	// Mode is the SSL mode to use.
	Mode string `json:"mode,omitempty"`
	// ServerName ensures that the certificate matches the given hostname the client is connecting to.
	ServerName string `json:"serverName,omitempty"`
	// CASecretRef is an optional reference to a secret containing the CA certificate.
	CASecretRef *reference.LocalSecretReference `json:"caSecretRef,omitempty"`
	// ClientCertificateSecretRef is an optional reference to a secret containing the client certificate and key.
	ClientCertificateSecretRef *reference.LocalSecretReference `json:"clientCertificateSecretRef,omitempty"`
}

// DexIdentityProviderStorageNetworkDBSpec holds configuration for postgres and mysql storage.
type DexIdentityProviderStorageNetworkDBSpec struct {
	// Database is the name of the database to connect to.
	Database string `json:"database"`
	// CredentialsSecretRef is a reference to a secret containing the
	// username and password to use for authentication.
	CredentialsSecretRef reference.LocalSecretReference `json:"credentialsSecretRef"`
	// Host is the host to connect to.
	Host string `json:"host"`
	// Port is the port to connect to.
	Port int `json:"port"`
	// ConnectionTimeout is the maximum amount of time to wait for a connection to become available.
	ConnectionTimeout *metav1.Duration `json:"connectionTimeout,omitempty"`
	// MaxOpenConns is the maximum number of open connections to the database (default 5).
	MaxOpenConns *int `json:"maxOpenConns,omitempty"`
	// MaxIdleConns is the maximum number of connections in the idle connection pool (default 5).
	MaxIdleConns *int `json:"maxIdleConns,omitempty"`
	// ConnMaxLifetime is the maximum amount of time a connection may be reused (default forever).
	ConnMaxLifetime *metav1.Duration `json:"connMaxLifetime,omitempty"`
	// SSL holds optional TLS configuration for postgres.
	SSL *DexIdentityProviderStorageSSLSpec `json:"ssl,omitempty"`
}

type DexIdentityProviderStorageSpec struct {
	// Type is the storage type to use.
	// +kubebuilder:validation:Enum=memory;sqlite3;postgres
	Type DexIdentityProviderStorageType `json:"type"`
	// Sqlite3 holds the configuration for the sqlite3 storage type.
	Sqlite3 *DexIdentityProviderStorageSqlite3Spec `json:"sqlite3,omitempty"`
	// Postgres holds the configuration for the postgres storage type.
	Postgres *DexIdentityProviderStorageNetworkDBSpec `json:"postgres,omitempty"`
}
