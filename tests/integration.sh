#!/bin/sh
set -eu

# Locates the directory containing the operator sources.
find_root_dir() {
  local CURRENT_DIR="${PWD}"
  while [ "${CURRENT_DIR}" != "/" ]; do
    if [ -f "${CURRENT_DIR}/Earthfile" ]; then
      echo "${CURRENT_DIR}"
      return
    fi
    CURRENT_DIR=$(dirname "${CURRENT_DIR}")
  done

  exit 1
}

export ROOT_DIR="$(find_root_dir)"

PROMETHEUS_VERSION="v0.68.0"
CERT_MANAGER_VERSION="v1.12.0"

CLUSTER_NAME="dex-operator-$(date +%s | rhash --simple - | cut -f 1 -d ' ')"

clean_up() {
  echo 'Deleting k3d cluster'

  k3d cluster delete "${CLUSTER_NAME}" || true
}

if [ -z "${NO_CLEANUP:-}" ]; then
  trap clean_up EXIT
fi

if [ -z "${SKIP_BUILD:-}" ]; then
  echo 'Building operator image'

  (cd "${ROOT_DIR}" && earthly +docker --VERSION=latest-dev)
fi

echo 'Creating k3d cluster'

k3d cluster create "${CLUSTER_NAME}" --wait

echo 'Waiting for k3s setup to complete'

kubectl wait -n kube-system job/helm-install-traefik-crd --for=condition=complete --timeout=300s

echo 'Installing Prometheus CRDs'

kapp deploy -y -a prometheus-crds -f "https://github.com/prometheus-operator/prometheus-operator/releases/download/${PROMETHEUS_VERSION}/stripped-down-crds.yaml"

echo 'Installing Cert Manager'

kapp deploy -y -a cert-manager -f "https://github.com/cert-manager/cert-manager/releases/download/${CERT_MANAGER_VERSION}/cert-manager.yaml"

echo 'Loading operator image into cluster'

k3d image import -c "${CLUSTER_NAME}" ghcr.io/gpu-ninja/dex-operator:latest-dev

echo 'Installing operator'

ytt --data-value version=latest-dev -f "${ROOT_DIR}/hack/set-version.yaml" -f "${ROOT_DIR}/config" | kapp deploy -y -a dex-operator -f -

echo 'Running tests'

(cd "${ROOT_DIR}/tests" && go test -v ./...)