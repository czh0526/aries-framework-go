package ecdh

import (
	"fmt"
	"github.com/tink-crypto/tink-go/v2/core/registry"
)

func init() {
	err := registry.RegisterKeyManager(newECDHNISTPAESPrivateKeyManager())
	if err != nil {
		panic(fmt.Sprintf("ecdh.init() failed: %v", err))
	}

	err = registry.RegisterKeyManager(newECDHNISTPAESPublicKeyManager())
	if err != nil {
		panic(fmt.Sprintf("ecdh.init() failed: %v", err))
	}

	err = registry.RegisterKeyManager(newX25519ECDHKWPrivateKeyManager())
	if err != nil {
		panic(fmt.Sprintf("ecdh.init() failed: %v", err))
	}

	err = registry.RegisterKeyManager(newX25519ECDHKWPublicKeyManager())
	if err != nil {
		panic(fmt.Sprintf("ecdh.init() failed: %v", err))
	}
}
