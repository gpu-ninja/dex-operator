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

* [cert-manager](https://cert-manager.io/docs/installation/)
* [kapp](https://carvel.dev/kapp/)

### Installing

```shell
kapp deploy -a dex-operator -f config/
```

### Starting a Dex Server

```shell
kubectl apply -f examples/issuer-ca.yaml \
  -f examples/issuer-api-ca.yaml \
  -f examples/certificate-demo.yaml \
  -f examples/certificate-demo-operator-client.yaml \
  -f examples/secret-ldap-bind-credentials.yaml \
  -f examples/dexidentityprovider-demo.yaml
```

### Creating an OAuth2 Client

```shell
kubectl apply -f examples/dexoauth2client-demo.yaml
```