module github.com/czh0526/aries-framework-go/component/storage/mysql

go 1.23.7

require (
	github.com/czh0526/aries-framework-go/spi v0.0.0-00010101000000-000000000000
	github.com/go-sql-driver/mysql v1.5.0
)

replace github.com/czh0526/aries-framework-go/spi => ../../../spi
