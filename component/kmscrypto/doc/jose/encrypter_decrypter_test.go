package jose

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/ecdh"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/keyio"
	ecdhpb "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/jwkkid"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/kmsdidkey"
	mockkms "github.com/czh0526/aries-framework-go/component/kmscrypto/mock/kms"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"github.com/go-jose/go-jose/v3"
	"github.com/stretchr/testify/require"
	hybrid "github.com/tink-crypto/tink-go/v2/hybrid/subtle"
	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	tinksubtle "github.com/tink-crypto/tink-go/v2/subtle"
	"math/big"
	"strings"
	"testing"
)

const (
	EnvelopeEncodingType       = "application/didcomm-encrypted+json"
	DIDCommContentEncodingType = "application/didcomm-plain+json"

	compactSerialization   = "Compact"
	fullSerialization      = "Full"
	flattenedSerialization = "Flattened"
)

func TestInteropWithGoJoseEncryptAndLocalJoseDecrypt(t *testing.T) {
	recECKeys, recKHs, recKIDs, _ := createRecipients(t, 3)
	gjRecipients := convertToGoJoseRecipients(t, recECKeys, recKIDs)

	c, k := createCryptoAndKMSServices(t, recKHs)

	eo := &jose.EncrypterOptions{}
	gjEncrypter, err := jose.NewMultiEncrypter(jose.A256GCM, gjRecipients,
		eo.WithType(EnvelopeEncodingType))
	require.NoError(t, err)

	pt := []byte("Test secret message")
	aad := []byte("Test some auth data")

	gjJWEEncrypter, err := gjEncrypter.EncryptWithAuthData(pt, aad)
	require.NoError(t, err)

	gjSerializedJWE := gjJWEEncrypter.FullSerialize()
	require.NoError(t, err)

	fmt.Printf("Go Jose Encrypt => \n%s\n", gjSerializedJWE)
	localJWE, err := Deserialize(gjSerializedJWE)
	require.NoError(t, err)

	t.Run("Decrypting JWE message encrypted by go-joes test success", func(t *testing.T) {
		jweDecrypter := NewJWEDecrypt(nil, c, k)

		var msg []byte

		msg, err = jweDecrypter.Decrypt(localJWE)
		require.NoError(t, err)
		require.Equal(t, pt, msg)
	})
}

func TestInteropWithLocalJoseEncryptAndGoJoseDecrypt(t *testing.T) {
	c, err := tinkcrypto.New()
	require.NoError(t, err)

	// 构建两个 Recipients（只有公钥）
	recECKeys, _, _, _ := createRecipients(t, 2)
	// 构建第三个 Recipients (有私钥)
	rec3PrivKey, err := ecdsa.GenerateKey(tinksubtle.GetCurve(recECKeys[0].Curve), rand.Reader)
	require.NoError(t, err)

	// 收集三个 Recipients 的公钥
	recECKeys = append(recECKeys, &spicrypto.PublicKey{
		X:     rec3PrivKey.PublicKey.X.Bytes(),
		Y:     rec3PrivKey.PublicKey.Y.Bytes(),
		Curve: rec3PrivKey.PublicKey.Curve.Params().Name,
		Type:  "EC",
	})

	// 构建 Encrypter
	jweEncrypter, err := NewJWEEncrypt(A256GCM, EnvelopeEncodingType, DIDCommContentEncodingType,
		"", nil, recECKeys, c)
	require.NoError(t, err, "NewJWEEncrypt should not fail with non empty recipientPubKeys")

	// 使用 Encrypter 加密数据，构建 JSON Web Encryption 对象
	pt := []byte("some msg")
	jwe, err := jweEncrypter.EncryptWithAuthData(pt, []byte("aad value"))
	require.NoError(t, err)
	require.Equal(t, len(recECKeys), len(jwe.Recipients))

	// 将 JSON Web Encryption 对象序列化
	serializedJWE, err := jwe.FullSerialize(json.Marshal)
	require.NoError(t, err)

	fmt.Printf("JSONWebEncryption => \n%s\n", serializedJWE)
	// 使用 jose 库反序列化 JSON Web Encryption 对象
	gjParsedJWE, err := jose.ParseEncrypted(serializedJWE)
	require.NoError(t, err)

	// 使用第三个 Recipient 的私钥，解密数据
	i, _, msg, err := gjParsedJWE.DecryptMulti(rec3PrivKey)
	require.NoError(t, err)
	require.EqualValues(t, pt, msg)

	require.Equal(t, 2, i)
}

func createRecipients(t *testing.T, nbOfEntities int) (
	[]*spicrypto.PublicKey, map[string]*keyset.Handle, []string, []string) {
	return createRecipientsByKeyTemplate(t, nbOfEntities,
		ecdh.NISTP256ECDHKWKeyTemplate(),
		spikms.NISTP256ECDHKWType)
}

func createRecipientsByKeyTemplate(t *testing.T, nbOfEntities int, kt *tinkpb.KeyTemplate,
	keyType spikms.KeyType) ([]*spicrypto.PublicKey, map[string]*keyset.Handle, []string, []string) {
	t.Helper()

	r := make([]*spicrypto.PublicKey, 0)
	rKH := make(map[string]*keyset.Handle)
	rKID := make([]string, 0)
	rDIDKey := make([]string, 0)

	for i := 0; i < nbOfEntities; i++ {
		mrKey, kh, kid, didKey := createAndMarshalEntityKey(t, kt, keyType)

		ecPubKey := new(spicrypto.PublicKey)
		err := json.Unmarshal(mrKey, ecPubKey)
		require.NoError(t, err)

		ecPubKey.KID = kid
		rKH[kid] = kh

		r = append(r, ecPubKey)
		rKID = append(rKID, kid)
		rDIDKey = append(rDIDKey, didKey)
	}

	return r, rKH, rKID, rDIDKey
}

func createAndMarshalEntityKey(t *testing.T, kt *tinkpb.KeyTemplate,
	keyType spikms.KeyType) ([]byte, *keyset.Handle, string, string) {
	t.Helper()

	kh, err := keyset.NewHandle(kt)
	require.NoError(t, err)

	pubKH, err := kh.Public()
	require.NoError(t, err)

	buf := new(bytes.Buffer)
	pubKeyWriter := keyio.NewWriter(buf)
	require.NotEmpty(t, pubKeyWriter)

	err = pubKH.WriteWithNoSecrets(pubKeyWriter)
	require.NoError(t, err)

	mKeyBytes := buf.Bytes()

	kid, err := jwkkid.CreateKID(mKeyBytes, keyType)
	require.NoError(t, err)

	didKey, err := kmsdidkey.BuildDIDKeyByKeyType(mKeyBytes, keyType)
	require.NoError(t, err)

	printKey(t, mKeyBytes, kid)

	return mKeyBytes, kh, kid, didKey
}

func printKey(t *testing.T, mPubKey []byte, kid string) {
	t.Helper()

	pubKey := new(spicrypto.PublicKey)
	err := json.Unmarshal(mPubKey, pubKey)
	require.NoError(t, err)

	switch pubKey.Type {
	case ecdhpb.KeyType_EC.String():
		t.Logf("** EC key: %s, kid: %s", getPrintedECPubKey(t, pubKey), kid)
	case ecdhpb.KeyType_OKP.String():
		t.Logf("** X25519 key: %s, kid: %s", getPrintedX25519PubKey(t, pubKey), kid)
	default:
		t.Errorf("not supported key type: %s", pubKey.Type)
	}
}

func prettyPrint(msg []byte) (string, error) {
	var prettyJSON bytes.Buffer

	err := json.Indent(&prettyJSON, msg, "", "\t")
	if err != nil {
		return "", err
	}

	return prettyJSON.String(), nil
}

func getPrintedECPubKey(t *testing.T, pubKey *spicrypto.PublicKey) string {
	crv, err := hybrid.GetCurve(pubKey.Curve)
	require.NoError(t, err)

	j := jose.JSONWebKey{
		Key: &ecdsa.PublicKey{
			Curve: crv,
			X:     new(big.Int).SetBytes(pubKey.X),
			Y:     new(big.Int).SetBytes(pubKey.Y),
		},
	}

	jwkByte, err := j.MarshalJSON()
	require.NoError(t, err)
	jwkStr, err := prettyPrint(jwkByte)
	require.NoError(t, err)

	return jwkStr
}

func getPrintedX25519PubKey(t *testing.T, pubKey *spicrypto.PublicKey) string {
	j := jose.JSONWebKey{
		Key: ed25519.PublicKey(pubKey.X),
	}

	jwkByte, err := j.MarshalJSON()
	require.NoError(t, err)

	jwkStr, err := prettyPrint(jwkByte)
	require.NoError(t, err)

	return strings.Replace(jwkStr, "Ed25519", "X25519", 1)
}

func convertToGoJoseRecipients(t *testing.T, keys []*spicrypto.PublicKey,
	kids []string) []jose.Recipient {
	t.Helper()

	var joseRecipients []jose.Recipient

	for i, key := range keys {
		c := tinksubtle.GetCurve(key.Curve)
		gjKey := jose.Recipient{
			KeyID:     kids[i],
			Algorithm: jose.ECDH_ES_A256KW,
			Key: &ecdsa.PublicKey{
				Curve: c,
				X:     new(big.Int).SetBytes(key.X),
				Y:     new(big.Int).SetBytes(key.Y),
			},
		}

		joseRecipients = append(joseRecipients, gjKey)
	}

	return joseRecipients
}

func createCryptoAndKMSServices(t *testing.T, keys map[string]*keyset.Handle) (
	spicrypto.Crypto, spikms.KeyManager) {
	c, err := tinkcrypto.New()
	require.NoError(t, err)

	k := &mockKMSGetter{
		keys: keys,
	}

	return c, k
}

type mockKMSGetter struct {
	mockkms.KeyManager
	keys map[string]*keyset.Handle
}

func (k *mockKMSGetter) Get(kid string) (interface{}, error) {
	return k.keys[kid], nil
}
