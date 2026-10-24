package vc

import (
	"crypto/ed25519"

	"github.com/tpt-solutions/tpt-identity/pkg/did"
)

// Ed25519Keys returns every active Ed25519 verification key a DID document publishes. Revoked
// keys and keys of other types are skipped; malformed keys are skipped rather than failing the
// whole document, so a caller can still match a valid key elsewhere in the document.
func Ed25519Keys(doc *did.Document) []ed25519.PublicKey {
	var keys []ed25519.PublicKey
	for _, vm := range doc.VerificationMethod {
		if vm.Revoked || vm.Type != "Ed25519VerificationKey2020" || vm.PublicKeyMultibase == nil {
			continue
		}
		key, err := decodeMultibaseEd25519(*vm.PublicKeyMultibase)
		if err != nil {
			continue
		}
		keys = append(keys, key)
	}
	return keys
}
