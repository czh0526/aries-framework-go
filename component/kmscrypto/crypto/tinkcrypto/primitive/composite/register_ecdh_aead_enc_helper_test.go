package composite

import (
	"encoding/hex"
	cbchmacaead "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead"
	subtlecbchmacaead "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead/subtle"
	"github.com/stretchr/testify/require"
	"github.com/tink-crypto/tink-go/v2/aead"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"testing"
)

func TestAead(t *testing.T) {
	keyTemplates, keysSizes := newKeyTemplates()

	for i, kt := range keyTemplates {
		pt := random.GetRandomBytes(20)
		ad := random.GetRandomBytes(20)
		rEnc, err := NewRegisterCompositeAEADEncHelper(kt)
		require.NoError(t, err, "error generating a content encryption helper")

		keySize := uint32(keysSizes[i])
		sk := random.GetRandomBytes(keySize)
		a, err := rEnc.GetAEAD(sk)
		require.NoError(t, err, "error getting AEAD primitive")

		ct, err := a.Encrypt(pt, ad)
		require.NoError(t, err, "error encrypting")

		dt, err := a.Decrypt(ct, ad)
		require.NoError(t, err, "error decrypting")

		require.EqualValuesf(t, pt, dt, "decryption not inverse of encryption, \n want: %s, \n got: %s",
			hex.Dump(pt), hex.Dump(dt))
	}
}

func newKeyTemplates() ([]*tinkpb.KeyTemplate, []int) {
	twoKeys := 2

	return []*tinkpb.KeyTemplate{
			//aead.ChaCha20Poly1305KeyTemplate(),
			//aead.XChaCha20Poly1305KeyTemplate(),
			aead.AES256GCMKeyTemplate(),
			aead.AES128GCMKeyTemplate(),
			cbchmacaead.AES128CBCHMACSHA256KeyTemplate(),
			cbchmacaead.AES192CBCHMACSHA384KeyTemplate(),
			cbchmacaead.AES256CBCHMACSHA384KeyTemplate(),
			cbchmacaead.AES256CBCHMACSHA512KeyTemplate(),
		},
		[]int{
			//chacha20poly1305.KeySize,
			//chacha20poly1305.KeySize,
			subtlecbchmacaead.AES256Size,
			subtlecbchmacaead.AES128Size,
			subtlecbchmacaead.AES128Size * twoKeys,
			subtlecbchmacaead.AES192Size * twoKeys,
			subtlecbchmacaead.AES256Size + subtlecbchmacaead.AES192Size,
			subtlecbchmacaead.AES256Size * twoKeys,
		}
}
