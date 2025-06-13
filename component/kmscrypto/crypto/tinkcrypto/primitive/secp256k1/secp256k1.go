package secp256k1

import (
	"fmt"
	"github.com/tink-crypto/tink-go/v2/core/registry"
)

func init() {
	if err := registry.RegisterKeyManager(newSecp256K2SignerKeyManager()); err != nil {
		panic(fmt.Sprintf("secp256k1 signer init() failed, err = %v", err))
	}
	if err := registry.RegisterKeyManager(newSecp256K1VerifierKeyManager()); err != nil {
		panic(fmt.Sprintf("secp256k1 verify init() failed, err = %v", err))
	}
}
