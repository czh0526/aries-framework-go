package aries

import (
	"github.com/czh0526/aries-framework-go/component/storage/mysql"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
)

func storeProvider() spistorage.Provider {
	p, err := mysql.NewProvider(
		"root:123456@tcp(127.0.0.1:3306)/?interpolateParams=true&multiStatements=true")
	if err != nil {
		panic(err)
	}

	return p
}
