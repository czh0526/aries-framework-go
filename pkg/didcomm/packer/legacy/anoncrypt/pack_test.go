package anoncrypt

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms/localkms"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/secretlock/noop"
	"github.com/czh0526/aries-framework-go/component/storage/mysql"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
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

func newLocalKMS(t *testing.T) *localkms.LocalKMS {

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

func TestPack(t *testing.T) {
	localKms := newLocalKMS(t)

	recKey, _, err := localKms.ExportPubKeyBytes("XnA20h63eW72hIgET2TmrIt0WZ4YnZTObZTqNu0cmJ4")
	require.NoError(t, err)

	t.Run("Success: pack then unpack, same packer", func(t *testing.T) {
		packer := newWithKMSAndCrypto(t, localKms)
		msgIn := []byte(`{
"@id":"61bd7e15-27c3-43b0-8941-2b4519746405",
"@type":"https://didcomm.org/introduce/1.0/proposal",
"to":{"name":"Carol"}}`)

		var (
			enc []byte
			env *transport.Envelope
		)

		enc, err = packer.Pack("", msgIn, nil, [][]byte{recKey})
		require.NoError(t, err)
		fmt.Printf("envelope ==> %s\n", enc)
		env, err = packer.Unpack(enc)
		require.NoError(t, err)
		fmt.Sprintf("%#v\n", env)
	})
}
