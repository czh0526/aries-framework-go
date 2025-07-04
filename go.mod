module github.com/czh0526/aries-framework-go

go 1.23.7

require (
	github.com/czh0526/aries-framework-go/component/kmscrypto v0.0.0-00010101000000-000000000000
	github.com/czh0526/aries-framework-go/component/models v0.0.0-00010101000000-000000000000
	github.com/czh0526/aries-framework-go/component/storage/mysql v0.0.0-00010101000000-000000000000
	github.com/czh0526/aries-framework-go/component/vdr v0.0.0-00010101000000-000000000000
	github.com/czh0526/aries-framework-go/spi v0.0.0-20250702110920-72cb70592d42
	github.com/google/uuid v1.3.0
	github.com/stretchr/testify v1.10.0
)

require (
	github.com/btcsuite/btcutil v1.0.3-0.20201208143702-a53e38424cce
	github.com/piprate/json-gold v0.5.0
)

require (
	github.com/IBM/mathlib v0.0.2 // indirect
	github.com/aead/siphash v1.0.1 // indirect
	github.com/btcsuite/btcd v0.22.3 // indirect
	github.com/btcsuite/btcd/chaincfg/chainhash v1.0.1 // indirect
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f // indirect
	github.com/btcsuite/go-socks v0.0.0-20170105172521-4720035b7bfd // indirect
	github.com/btcsuite/goleveldb v1.0.0 // indirect
	github.com/btcsuite/snappy-go v1.0.0 // indirect
	github.com/btcsuite/websocket v0.0.0-20150119174127-31079b680792 // indirect
	github.com/btcsuite/winsvc v1.0.0 // indirect
	github.com/consensys/bavard v0.1.13 // indirect
	github.com/consensys/gnark-crypto v0.9.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/decred/dcrd/lru v1.0.0 // indirect
	github.com/go-jose/go-jose/v3 v3.0.4 // indirect
	github.com/go-sql-driver/mysql v1.5.0 // indirect
	github.com/google/tink/go v1.7.0 // indirect
	github.com/hyperledger/fabric-amcl v0.0.0-20210603140002-2670f91851c8 // indirect
	github.com/jessevdk/go-flags v1.4.0 // indirect
	github.com/jrick/logrotate v1.0.0 // indirect
	github.com/kkdai/bstream v0.0.0-20161212061736-f391b8402d23 // indirect
	github.com/mmcloughlin/addchain v0.4.0 // indirect
	github.com/mr-tron/base58 v1.1.0 // indirect
	github.com/multiformats/go-base32 v0.0.3 // indirect
	github.com/multiformats/go-base36 v0.1.0 // indirect
	github.com/multiformats/go-multibase v0.2.0 // indirect
	github.com/pkg/errors v0.8.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/pquerna/cachecontrol v0.0.0-20180517163645-1555304b9b35 // indirect
	github.com/tink-crypto/tink-go/v2 v2.4.0 // indirect
	golang.org/x/crypto v0.35.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	rsc.io/tmplfunc v0.0.3 // indirect
)

replace (
	github.com/czh0526/aries-framework-go => ./
	github.com/czh0526/aries-framework-go/component/kmscrypto => ./component/kmscrypto
	github.com/czh0526/aries-framework-go/component/models => ./component/models
	github.com/czh0526/aries-framework-go/component/storage/mysql => ./component/storage/mysql
	github.com/czh0526/aries-framework-go/component/vdr => ./component/vdr
	github.com/czh0526/aries-framework-go/spi => ./spi
)
