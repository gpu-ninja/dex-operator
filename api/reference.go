package api

import (
	"context"

	"github.com/gpu-ninja/operator-utils/reference"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// +kubebuilder:object:generate=true
type DexIdentityProviderReference struct {
	// Name of the referenced DexIdentityProvider.
	Name string `json:"name"`
	// Namespace is the optional namespace of the referenced DexIdentityProvider.
	Namespace string `json:"namespace,omitempty"`
}

func (ref *DexIdentityProviderReference) Resolve(ctx context.Context, reader client.Reader, scheme *runtime.Scheme, parent runtime.Object) (runtime.Object, error) {
	objRef := &reference.ObjectReference{
		Name:      ref.Name,
		Namespace: ref.Namespace,
		Kind:      "DexIdentityProvider",
	}

	return objRef.Resolve(ctx, reader, scheme, parent)
}
