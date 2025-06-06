package aead

const (
	aesCBCHMACAEADKeyVersion = 0
	aesCBCHMACAEADTypeURL    = "type.hyperledger.org/hyperledger.aries.crypto.tink.AesCbcHmacAeadKey"
	minHMACKeySizeInBytes    = 16
	minTagSizeInBytes        = 10

	maxTagSizeSHA1   = 20
	maxTagSizeSHA224 = 28
	maxTagSizeSHA256 = 32
	maxTagSizeSHA384 = 48
	maxTagSizeSHA512 = 64
)
