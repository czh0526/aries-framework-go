package aead

import (
	"fmt"
	aeadpb "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/aes_cbc_hmac_aead_go_proto"
	"github.com/stretchr/testify/require"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"google.golang.org/protobuf/proto"
	"testing"
)

func TestNewKeyMultipleTimes(t *testing.T) {
	keyTemplate := AES128CBCHMACSHA256KeyTemplate()
	aeadKeyFormat := new(aeadpb.AesCbcHmacAeadKeyFormat)
	err := proto.Unmarshal(keyTemplate.Value, aeadKeyFormat)
	require.NoError(t, err, "cannot unmarshal AES128CBCHMACSHA256 key template")

	keyManager, err := registry.GetKeyManager(aesCBCHMACAEADTypeURL)
	require.NoError(t, err, "cannot obtain AES-CBC-HMAC-AEAD key manager: %s", err)

	keys := make(map[string]bool)

	const numTests = 24
	for i := 0; i < numTests/2; i++ {
		k, err := keyManager.NewKey(keyTemplate.Value)
		require.NoError(t, err, "cannot serialize key")

		sk, err := proto.Marshal(k)
		require.NoErrorf(t, err, "cannot serialze key")

		key := new(aeadpb.AesCbcHmacAeadKey)
		err = proto.Unmarshal(sk, key)
		require.NoError(t, err)

		keys[string(key.AesCbcKey.KeyValue)] = true
		keys[string(key.HmacKey.KeyValue)] = true

		require.EqualValuesf(t, 16, len(key.AesCbcKey.KeyValue), fmt.Sprintf("unexpected AES key size: get: %d, want: 16",
			len(key.AesCbcKey.KeyValue)))
		require.EqualValuesf(t, 16, len(key.HmacKey.KeyValue), fmt.Sprintf("unexpected HMAC key size: get: %d, want: 32",
			len(key.HmacKey.KeyValue)))
	}
}
