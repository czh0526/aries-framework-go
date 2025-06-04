module github.com/czh0526/aries-framework-go/component/vdr

go 1.23.7

require (
	github.com/czh0526/aries-framework-go/component/models v0.0.0-00010101000000-000000000000
	github.com/czh0526/aries-framework-go/spi v0.0.0-00010101000000-000000000000
	github.com/stretchr/testify v1.8.0
)

require (
	github.com/czh0526/aries-framework-go/component/kmscrypto v0.0.0-00010101000000-000000000000 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-jose/go-jose/v3 v3.0.4 // indirect
	github.com/mr-tron/base58 v1.1.0 // indirect
	github.com/multiformats/go-base32 v0.0.3 // indirect
	github.com/multiformats/go-base36 v0.1.0 // indirect
	github.com/multiformats/go-multibase v0.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/crypto v0.35.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace (
	github.com/czh0526/aries-framework-go/component/kmscrypto => ../../component/kmscrypto
	github.com/czh0526/aries-framework-go/component/models => ../../component/models
	github.com/czh0526/aries-framework-go/spi => ../../spi
)
