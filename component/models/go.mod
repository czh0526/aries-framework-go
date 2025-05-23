module github.com/czh0526/aries-framework-go/component/models

go 1.23.7

require (
	github.com/czh0526/aries-framework-go/component/kmscrypto v0.0.0-00010101000000-000000000000
	github.com/multiformats/go-multibase v0.2.0
	github.com/piprate/json-gold v0.5.0
)

require (
	github.com/btcsuite/btcd v0.20.1-beta // indirect
	github.com/btcsuite/btcutil v1.0.2 // indirect
	github.com/go-jose/go-jose/v3 v3.0.4 // indirect
	github.com/mr-tron/base58 v1.1.0 // indirect
	github.com/multiformats/go-base32 v0.0.3 // indirect
	github.com/multiformats/go-base36 v0.1.0 // indirect
	github.com/pquerna/cachecontrol v0.0.0-20180517163645-1555304b9b35 // indirect
	golang.org/x/crypto v0.19.0 // indirect
)

replace (
	github.com/czh0526/aries-framework-go/component/kmscrypto => ../kmscrypto
	github.com/czh0526/aries-framework-go/spi => ../../spi
)
