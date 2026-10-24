package api

import (
	"context"
	"crypto/ed25519"

	"github.com/tpt-solutions/tpt-identity/internal/resolver"
	"github.com/tpt-solutions/tpt-identity/oidc"
	vcpkg "github.com/tpt-solutions/tpt-identity/pkg/vc"
)

// holderKeyResolver resolves a holder DID through the shared resolver and returns the Ed25519
// keys its document publishes. The OID4VCI credential endpoint uses it to check key proofs.
func holderKeyResolver(res *resolver.Resolver) oidc.HolderKeyResolver {
	return func(_ context.Context, holderDID string) ([]ed25519.PublicKey, error) {
		doc, err := res.Resolve(holderDID)
		if err != nil {
			return nil, err
		}
		return vcpkg.Ed25519Keys(doc), nil
	}
}
