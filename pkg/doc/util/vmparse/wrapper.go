package vmparse

import (
	"github.com/czh0526/aries-framework-go/component/models/did"
	"github.com/czh0526/aries-framework-go/component/models/did/util/vmparse"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
)

func VMToBytesTypeCrv(vm *did.VerificationMethod) ([]byte, spikms.KeyType, string, error) {
	return vmparse.VMToBytesTypeCrv(vm)
}
