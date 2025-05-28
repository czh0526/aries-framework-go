module github.com/czh0526/aries-framework-go/component/kmscrypto

go 1.23.7

require (
	github.com/IBM/mathlib v0.0.2
	github.com/btcsuite/btcd v0.20.1-beta
	github.com/btcsuite/btcutil v1.0.2
	github.com/czh0526/aries-framework-go/spi v0.0.0-00010101000000-000000000000
	github.com/go-jose/go-jose/v3 v3.0.4
	github.com/stretchr/testify v1.8.0
)

require (
	github.com/consensys/bavard v0.1.13 // indirect
	github.com/consensys/gnark-crypto v0.9.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/hyperledger/fabric-amcl v0.0.0-20210603140002-2670f91851c8 // indirect
	github.com/mmcloughlin/addchain v0.4.0 // indirect
	github.com/pkg/errors v0.8.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/crypto v0.19.0 // indirect
	golang.org/x/sys v0.17.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	rsc.io/tmplfunc v0.0.3 // indirect
)

replace github.com/czh0526/aries-framework-go/spi => ../../spi
