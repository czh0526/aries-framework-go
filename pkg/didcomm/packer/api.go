package packer

import (
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
)

type Provider interface {
	KMS() spikms.KeyManager
	Crypto() spicrypto.Crypto
	StorageProvider() spistorage.Provider
	VDRegistry() vdrapi.Registry
}

type Packer interface {
	EncodingType() string
}

type Creator func(p Provider) (Packer, error)
