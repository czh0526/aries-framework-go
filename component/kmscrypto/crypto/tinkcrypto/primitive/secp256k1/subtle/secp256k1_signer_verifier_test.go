package subtle

import (
	"crypto/ecdsa"
	"crypto/rand"
	"github.com/stretchr/testify/require"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"testing"
)

func TestSignVerify(t *testing.T) {

	data := random.GetRandomBytes(20)
	hash := "SHA256"
	curve := "SECP256K1"
	encodings := []string{"Bitcoin_DER", "Bitcoin_IEEE_P1363"}

	for _, encoding := range encodings {
		priv, err := ecdsa.GenerateKey(GetCurve(curve), rand.Reader)
		require.NoError(t, err)

		// 使用公私钥对象，生成实例
		signer, err := NewSecp256K1SignerFromPrivateKey(hash, encoding, priv)
		require.NoError(t, err)

		verifier, err := NewSecp256K1VerifierFromPublicKey(hash, encoding, &priv.PublicKey)
		require.NoError(t, err)

		signature, err := signer.Sign(data)
		require.NoError(t, err, "unexpected error when signing")

		err = verifier.Verify(signature, data)
		require.NoError(t, err, "unexpected error when verifying")

		// 使用字节数组，生成实例
		signer, err = NewSecp256K1Signer(hash, curve, encoding, priv.D.Bytes())
		require.NoError(t, err)

		verifier, err = NewSecp256K1Verifier(hash, curve, encoding, priv.X.Bytes(), priv.Y.Bytes())
		require.NoError(t, err)

		signature, err = signer.Sign(data)
		require.NoError(t, err, "unexpected error when signing")

		err = verifier.Verify(signature, data)
		require.NoError(t, err, "unexpected error when verifying")
	}
}
