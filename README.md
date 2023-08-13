# dex-operator

A Kubernetes operator for deploying and managing [Dex IdP](https://dexidp.io/).

## Supported Features

Currently, the following features are supported. There's a long tail of different
connectors and storage backends supported by Dex, so if you need something that's
not listed here, please open an issue or submit a PR!

### Storage

* SQLite3
* PostgreSQL

### Connectors

* [LDAP](https://dexidp.io/docs/connectors/ldap/)
* [OpenID Connect (OIDC)](https://dexidp.io/docs/connectors/oidc/)

## Getting Started

### Prerequisites

* [kapp](https://carvel.dev/kapp/)

### Installing

#### Cert-Manager

```shell
kapp deploy -a cert-manager -f https://github.com/cert-manager/cert-manager/releases/download/v1.12.0/cert-manager.yaml
```

#### Operator

```shell
kapp deploy -a dex-operator -f https://github.com/gpu-ninja/dex-operator/releases/latest/download/dex-operator.yaml
```

### Starting a Dex Server

```shell
kubectl apply -f examples -l app.kubernetes.io/component=server
```

### Creating an OAuth2 Client

```shell
kubectl apply -f examples -l app.kubernetes.io/component=client
```