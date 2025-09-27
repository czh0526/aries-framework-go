package makemockdoc

import (
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/jwkkid"
	didmodel "github.com/czh0526/aries-framework-go/component/models/did"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"github.com/stretchr/testify/require"
	"testing"
)

const (
	DefaultKID                 = "#key-1"
	ed25519VerificationKey2018 = "Ed25519VerificationKey2018"
	jsonWebKey2020             = "JSONWebKey2020"
)

func MakeMockDoc(t *testing.T, keyManager spikms.KeyManager, docDID string, keyType spikms.KeyType) *didmodel.Doc {
	t.Helper()

	_, pkb, err := keyManager.CreateAndExportPubKeyBytes(keyType)
	require.NoError(t, err)

	var pkJWK *jwk.JWK

	var vm *didmodel.VerificationMethod

	if keyType == spikms.ED25519Type {
		vm = &didmodel.VerificationMethod{
			ID:         DefaultKID,
			Controller: docDID,
			Type:       ed25519VerificationKey2018,
			Value:      pkb,
		}
	} else {
		pkJWK, err = jwkkid.BuildJWK(pkb, keyType)
		require.NoError(t, err)

		pkJWK.Algorithm = "ECDSA"

		vm, err = didmodel.NewVerificationMethodFromJWK(DefaultKID, jsonWebKey2020, docDID, pkJWK)
		require.NoError(t, err)
	}

	newDoc := &didmodel.Doc{
		ID: docDID,
		AssertionMethod: []didmodel.Verification{
			{
				VerificationMethod: *vm,
				Relationship:       didmodel.AssertionMethod,
			},
		},
		VerificationMethod: []didmodel.VerificationMethod{
			*vm,
		},
	}

	return newDoc
}
