package authcrypt

import (
	"fmt"
	comp_jose "github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms/localkms"
	comp_mockkms "github.com/czh0526/aries-framework-go/component/kmscrypto/mock/kms"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/secretlock/noop"
	comp_mockstorage "github.com/czh0526/aries-framework-go/component/storage/mock"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
	"github.com/czh0526/aries-framework-go/pkg/doc/jose"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestAuthCryptPackerSuccess(t *testing.T) {
	k := createKMS(t)

	tests := []struct {
		name    string
		keyType spikms.KeyType
		encAlg  comp_jose.EncAlg
		cty     string
	}{
		{
			name:    "authcrypt using NISTP256ECDHKW and AES128CBC_HMAC_SHA256",
			keyType: spikms.NISTP256ECDHKWType,
			encAlg:  jose.A128CBCHS256,
			cty:     transport.MediaTypeV1PlaintextPayload,
		},
	}

	t.Parallel()

	for _, tt := range tests {
		t.Run(fmt.Sprintf("running %s", tt.name), func(t *testing.T) {
			
		})
	}
}

func createKMS(t *testing.T) *localkms.LocalKMS {
	t.Helper()

	kmsProvider, err := comp_mockkms.NewProviderForKMS(
		comp_mockstorage.NewMockStoreProvider(),
		&noop.NoLock{},
	)
	require.NoError(t, err)

	kms, err := localkms.New("local-lock://test/uri", kmsProvider)
	require.NoError(t, err)

	return kms
}
