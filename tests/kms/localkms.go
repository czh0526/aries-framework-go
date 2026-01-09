package kms

import (
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms/localkms"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/secretlock/noop"
	"github.com/czh0526/aries-framework-go/component/storage/mysql"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	spisecretlock "github.com/czh0526/aries-framework-go/spi/secretlock"
	"github.com/stretchr/testify/require"
	"testing"
)

type testProvider struct {
	storeProvider      spikms.Store
	secretLockProvider spisecretlock.Service
}

func (p *testProvider) StorageProvider() spikms.Store {
	return p.storeProvider
}

func (p *testProvider) SecretLock() spisecretlock.Service {
	return p.secretLockProvider
}

func NewLocalKMS(t *testing.T) *localkms.LocalKMS {

	dbProvider, err := mysql.NewProvider("root:123456@tcp(127.0.0.1:3306)/aries?charset=utf8mb4&parseTime=True&loc=Local")
	require.NoError(t, err)

	dbStore, err := kms.NewAriesProviderWrapper(dbProvider)
	require.NoError(t, err)

	p := testProvider{
		storeProvider:      dbStore,
		secretLockProvider: &noop.NoLock{},
	}

	mainLockURI := "local-lock://test/uri/"
	localKms, err := localkms.New(mainLockURI, &p)
	require.NoError(t, err)

	return localKms
}
