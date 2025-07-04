module github.com/czh0526/aries-framework-go/component/vdr

go 1.23.7

require (
	github.com/czh0526/aries-framework-go/component/models v0.0.0-20250704014650-3af35ecb5789
	github.com/czh0526/aries-framework-go/spi v0.0.0-20250702110920-72cb70592d42
	github.com/stretchr/testify v1.10.0
)

require (

)

replace (
	github.com/czh0526/aries-framework-go/spi => ../../spi
	github.com/czh0526/aries-framework-go/component/models => ../models
)
