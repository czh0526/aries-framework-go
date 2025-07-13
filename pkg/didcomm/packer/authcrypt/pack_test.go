package authcrypt

import (
	"encoding/json"
	"fmt"
	comp_jose "github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/kmsdidkey"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms/localkms"
	comp_mockkms "github.com/czh0526/aries-framework-go/component/kmscrypto/mock/kms"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/secretlock/noop"
	comp_mockstorage "github.com/czh0526/aries-framework-go/component/storage/mock"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
	"github.com/czh0526/aries-framework-go/pkg/doc/jose"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"github.com/stretchr/testify/require"
	"github.com/tink-crypto/tink-go/v2/keyset"
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
			createAndMarshalKeyByKeyType(t, k, tt.keyType)
		})
	}
}

func createAndMarshalKeyByKeyType(t *testing.T, kms spikms.KeyManager, kt spikms.KeyType) (
	string, string, []byte, *keyset.Handle) {
	t.Helper()

	kid, keyHandle, err := kms.Create(kt)
	require.NoError(t, err)

	kh, ok := keyHandle.(*keyset.Handle)
	require.True(t, ok)

	pubKeyBytes, err := exportPubKeyBytes(kh, kid)
	require.NoError(t, err)

	key := &spicrypto.PublicKey{}
	err = json.Unmarshal(pubKeyBytes, key)
	require.NoError(t, err)

	didKey, err := kmsdidkey.BuildDIDKeyByKeyType(pubKeyBytes, kt)
	require.NoError(t, err)

	key.KID = didKey
	mKey, err := json.Marshal(key)
	require.NoError(t, err)

	printKey(t, mKey, kh, kid, didKey)

	return kid, didKey, mKey, kh
}

func printKey(t *testing.T, mPubKey []byte, kh *keyset.Handle, kid, didKey string) {
	t.Helper()

	extractKey, err := extractPrivKey(kh)
}

func extractPrivKey(kh *keyset.Handle) (interface{}, error) {
	nistPECDHKWPrivkateKeyTypeURL := ""
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
