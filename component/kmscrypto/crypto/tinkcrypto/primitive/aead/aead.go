package aead

import (
	"fmt"
	"github.com/tink-crypto/tink-go/v2/core/registry"
)

func init() {
	if err := registry.RegisterKeyManager(newAESCBCHMACAEADKeyManager()); err != nil {
		panic(fmt.Sprintf("aead.init() failed: %s", err))
	}
}
