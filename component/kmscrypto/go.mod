module github.com/czh0526/aries-framework-go/component/kmscrypto

go 1.23.7

require (
	github.com/IBM/mathlib v0.0.2
	github.com/btcsuite/btcd v0.22.3
	github.com/btcsuite/btcutil v1.0.3-0.20201208143702-a53e38424cce
	github.com/czh0526/aries-framework-go/component/log v0.0.0-00010101000000-000000000000
	github.com/czh0526/aries-framework-go/spi v0.0.0-20250702110920-72cb70592d42
	github.com/go-jose/go-jose/v3 v3.0.4
	github.com/golang/mock v1.6.0
	github.com/golang/protobuf v1.5.4
	github.com/stretchr/testify v1.10.0
	github.com/tink-crypto/tink-go/v2 v2.4.0
	golang.org/x/crypto v0.35.0
	google.golang.org/protobuf v1.36.6
)

require (
	github.com/aead/siphash v1.0.1 // indirect
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
	github.com/hyperledger/fabric-amcl v0.0.0-20210603140002-2670f91851c8 // indirect
	github.com/jessevdk/go-flags v1.4.0 // indirect
	github.com/jrick/logrotate v1.0.0 // indirect
	github.com/kkdai/bstream v0.0.0-20161212061736-f391b8402d23 // indirect
	github.com/mmcloughlin/addchain v0.4.0 // indirect
	github.com/pkg/errors v0.8.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	rsc.io/tmplfunc v0.0.3 // indirect
)

replace (
	github.com/czh0526/aries-framework-go/component/log => ../../component/log
	github.com/czh0526/aries-framework-go/spi => ../../spi
)
