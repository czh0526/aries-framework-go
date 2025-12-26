module github.com/czh0526/aries-framework-go

go 1.23.9

require (
	github.com/czh0526/aries-framework-go/component/kmscrypto v0.0.0-20251123150327-e865d0a2866a
	github.com/czh0526/aries-framework-go/component/log v0.0.0-20251210110246-7d4f53f9c64c
	github.com/czh0526/aries-framework-go/component/models v0.0.0-20251224110511-bca6c87cc380
	github.com/czh0526/aries-framework-go/component/storage v0.0.0-20251123145407-d92bd878ebfd
	github.com/czh0526/aries-framework-go/component/storage/mysql v0.0.0-20251123160010-333d7ea42976
	github.com/czh0526/aries-framework-go/component/storageutil v0.0.0-20251208043106-351c7e6daee0
	github.com/czh0526/aries-framework-go/component/vdr v0.0.0-20251206042806-4eaf6ce264e2
	github.com/czh0526/aries-framework-go/spi v0.0.0-20251123160010-333d7ea42976
)

require (
	github.com/btcsuite/btcutil v1.0.3-0.20201208143702-a53e38424cce
	github.com/cenkalti/backoff/v4 v4.3.0
	github.com/go-jose/go-jose v2.6.3+incompatible
	github.com/go-jose/go-jose/v3 v3.0.4
	github.com/golang/mock v1.6.0
	github.com/google/uuid v1.6.0
	github.com/mitchellh/mapstructure v1.5.0
	github.com/piprate/json-gold v0.5.0
	github.com/rs/cors v1.11.1
	github.com/stretchr/testify v1.10.0
	github.com/tink-crypto/tink-go/v2 v2.4.0
	golang.org/x/crypto v0.35.0
	google.golang.org/protobuf v1.36.6
)

require (
	github.com/IBM/mathlib v0.0.2 // indirect
	github.com/btcsuite/btcd v0.22.3 // indirect
	github.com/consensys/bavard v0.1.13 // indirect
	github.com/consensys/gnark-crypto v0.9.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-sql-driver/mysql v1.5.0 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/hyperledger/fabric-amcl v0.0.0-20210603140002-2670f91851c8 // indirect
	github.com/mmcloughlin/addchain v0.4.0 // indirect
	github.com/mr-tron/base58 v1.1.0 // indirect
	github.com/multiformats/go-base32 v0.0.3 // indirect
	github.com/multiformats/go-base36 v0.1.0 // indirect
	github.com/multiformats/go-multibase v0.2.0 // indirect
	github.com/pkg/errors v0.8.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/pquerna/cachecontrol v0.0.0-20180517163645-1555304b9b35 // indirect
	github.com/teserakt-io/golang-ed25519 v0.0.0-20210104091850-3888c087a4c8 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20180127040702-4e3ac2762d5f // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xeipuuv/gojsonschema v1.2.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	gopkg.in/go-jose/go-jose.v2 v2.6.3 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	rsc.io/tmplfunc v0.0.3 // indirect
)

replace (
	github.com/czh0526/aries-framework-go/component/kmscrypto => ./component/kmscrypto
	github.com/czh0526/aries-framework-go/component/log => ./component/log
	github.com/czh0526/aries-framework-go/component/models => ./component/models
	github.com/czh0526/aries-framework-go/component/storage => ./component/storage
	github.com/czh0526/aries-framework-go/component/storage/mysql => ./component/storage/mysql
	github.com/czh0526/aries-framework-go/component/storageutil => ./component/storageutil
	github.com/czh0526/aries-framework-go/component/vdr => ./component/vdr
	github.com/czh0526/aries-framework-go/spi => ./spi
)
