package vmparse

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/component/models/did"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
)

const (
	jsonWebKey2020             = "JSONWebKey2020"
	jwsVerificationKey2020     = "JwsVerificationKey2020"
	ed25519VerificationKey2018 = "Ed25519VerificationKey2018"
)

func VMToBytesTypeCrv(vm *did.VerificationMethod) ([]byte, spikms.KeyType, string, error) {
	switch vm.Type {
	case ed25519VerificationKey2018:
		return vm.Value, spikms.ED25519Type, "Ed25519", nil
	case jsonWebKey2020, jwsVerificationKey2020:
		k := vm.JSONWebKey()

		kb, err := k.PublicKeyBytes()
		if err != nil {
			return nil, "", "", fmt.Errorf("getting []byte key for verification key: %w", err)
		}

		kt, err := k.KeyType()
		if err != nil {
			return nil, "", "", fmt.Errorf("getting kms.KeyType for verification key: %w", err)
		}

		return kb, kt, k.Crv, nil

	default:
		return nil, "", "", fmt.Errorf("vm.Type `%s` not supported", vm.Type)
	}
}
