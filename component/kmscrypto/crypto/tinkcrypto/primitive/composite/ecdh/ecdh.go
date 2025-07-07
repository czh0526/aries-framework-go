package ecdh

import "github.com/tink-crypto/tink-go/v2/core/registry"

func init() {
	err := registry.RegisterKeyManager(newECDHNISP)
}
