package localkms

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	mocksecretlock "github.com/czh0526/aries-framework-go/component/kmscrypto/mock/secretlock"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/secretlock/noop"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"testing"
)

func TestImportECDSAKey(t *testing.T) {
	k := createKMS(t)
	errPrefix := "import private EC key failed:"

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// 失败用例
	_, _, err = k.importECDSAKey(nil, spikms.ECDSAP256TypeDER)
	require.EqualError(t, err, errPrefix+" private key is nil")

	_, _, err = k.importECDSAKey(privKey, spikms.AES128GCM)
	require.EqualError(t, err, errPrefix+" invalid ECDSA key type", "importECDSAKey should fail with unsupported key type")

	// 成功用例
	_, _, err = k.importECDSAKey(privKey, spikms.ECDSAP256TypeDER)
	require.NoError(t, err)

	_, _, err = k.importECDSAKey(privKey, spikms.ECDSASecp256k1TypeIEEEP1363)
	require.NoError(t, err)
}

func TestImportEd25519Key(t *testing.T) {
	k := createKMS(t)
	errPrefix := "import private ED25519 key failed:"

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// 失败案例
	_, _, err = k.importEd25519Key(nil, spikms.ED25519Type)
	require.EqualError(t, err, errPrefix+" private key is nil")

	// 成功案例
	_, _, err = k.importEd25519Key(privateKey, spikms.ED25519Type)
	require.NoError(t, err)
}

func TestImportKeyset(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	errPrefix := "import private EC key failed:"
	flagTests := []struct {
		tcName        string
		kmsProvider   spikms.Provider
		ks            *tinkpb.Keyset
		expectedError string
	}{
		{
			tcName: "call importKeySet with nil keyset",
			kmsProvider: &mockProvider{
				storage: newInMemoryKMSStore(),
				secretLock: &mocksecretlock.MockSecretLock{
					ValEncrypt: "",
					ValDecrypt: "",
				},
			},
			expectedError: errPrefix + " encrypted failed: encrypted dek is empty",
		},
		{
			tcName: "call importKeySet with bad scretLock Encrypt",
			kmsProvider: &mockProvider{
				storage: newInMemoryKMSStore(),
				secretLock: &mocksecretlock.MockSecretLock{
					ValEncrypt: "",
					ErrEncrypt: fmt.Errorf("bad encryption"),
					ValDecrypt: "",
				},
			},
			expectedError: errPrefix + " encrypted failed: bad encryption",
			ks: &tinkpb.Keyset{
				PrimaryKeyId: 1,
				Key:          nil,
			},
		},
		{
			tcName: "call importKeySet with bad storage getKeySet call",
			kmsProvider: &mockProvider{
				storage: newInMemoryKMSStore(),
				secretLock: &mocksecretlock.MockSecretLock{
					ValEncrypt: "",
					ValDecrypt: "",
				},
			},
			expectedError: "import private EC key successful but failed to failed to get key from  store:",
			ks: &tinkpb.Keyset{
				PrimaryKeyId: 1,
				Key:          nil,
			},
		},
	}

	for _, tt := range flagTests {
		t.Run(tt.tcName, func(t *testing.T) {
			k, err := New(testMasterKeyURI, tt.kmsProvider)
			require.NoError(t, err)

			_, _, err = k.importKeySet(tt.ks)
			require.EqualError(t, err, tt.expectedError)
		})
	}
}

func createKMS(t *testing.T) *LocalKMS {
	t.Helper()

	p := &mockProvider{
		storage:    newInMemoryKMSStore(),
		secretLock: &noop.NoLock{},
	}

	k, err := New(testMasterKeyURI, p)
	require.NoError(t, err)

	return k
}
