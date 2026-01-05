package localkms

import (
	"encoding/base64"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/secretlock/noop"
	"github.com/czh0526/aries-framework-go/component/storage/mysql"
	"github.com/stretchr/testify/require"
	"testing"
)

func newLocalKMS(t *testing.T) *LocalKMS {

	dbProvider, err := mysql.NewProvider("root:123456@tcp(127.0.0.1:3306)/aries?charset=utf8mb4&parseTime=True&loc=Local")
	require.NoError(t, err)

	dbStore, err := kms.NewAriesProviderWrapper(dbProvider)
	require.NoError(t, err)

	p := testProvider{
		storeProvider:      dbStore,
		secretLockProvider: &noop.NoLock{},
	}

	mainLockURI := "local-lock://test/uri/"
	localKms, err := New(mainLockURI, &p)
	require.NoError(t, err)

	return localKms
}

func TestExportPrivateKey(t *testing.T) {
	localKms := newLocalKMS(t)

	exportEncPrivKeyBytes, err := localKms.exportEncPrivKeyBytes("XnA20h63eW72hIgET2TmrIt0WZ4YnZTObZTqNu0cmJ4")
	require.NoError(t, err)
	require.NotNil(t, exportEncPrivKeyBytes)

	fmt.Printf("exportEncPrivKeyBytes: %s\n", base64.RawURLEncoding.EncodeToString(exportEncPrivKeyBytes))
}
