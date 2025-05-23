module github.com/czh0526/aries-framework-go/compoment/kmscrypto

go 1.23.7

require (
	github.com/czh0526/aries-framework-go/spi v0.0.0-00010101000000-000000000000
	github.com/go-jose/go-jose/v3 v3.0.4
)

require golang.org/x/crypto v0.19.0 // indirect

replace github.com/czh0526/aries-framework-go/spi => ../../spi
