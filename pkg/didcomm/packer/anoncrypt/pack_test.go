package anoncrypt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/keyio"
	ecdhpb "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
	aries_jose "github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/kmsdidkey"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms/localkms"
	mockkms "github.com/czh0526/aries-framework-go/component/kmscrypto/mock/kms"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/secretlock/noop"
	mockstorage "github.com/czh0526/aries-framework-go/component/storage/mock"
	mockvdr "github.com/czh0526/aries-framework-go/component/vdr/mock"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
	mockprovider "github.com/czh0526/aries-framework-go/pkg/mock/provider"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"github.com/go-jose/go-jose/v3"
	"github.com/stretchr/testify/require"
	hybrid "github.com/tink-crypto/tink-go/v2/hybrid/subtle"
	"github.com/tink-crypto/tink-go/v2/keyset"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"
	"io"
	"strings"
	"testing"
)

func TestAnoncryptPackerSuccess(t *testing.T) {
	k := createKMS(t)

	tests := []struct {
		name    string
		keyType spikms.KeyType
		encAlg  aries_jose.EncAlg
		cty     string
	}{
		{
			name:    "anoncrypt using NISTP256ECDHKW and AS256-GCM",
			keyType: spikms.NISTP256ECDHKWType,
			encAlg:  aries_jose.A256GCM,
			cty:     transport.MediaTypeV1PlaintextPayload,
		},
		{
			name:    "anoncrypt using NISTP384ECDHKW and AS256-GCM",
			keyType: spikms.NISTP384ECDHKWType,
			encAlg:  aries_jose.A256GCM,
			cty:     transport.MediaTypeV1PlaintextPayload,
		},
		{
			name:    "anoncrypt uing NISTP521ECDHKW and AS256-GCM",
			keyType: spikms.NISTP521ECDHKWType,
			encAlg:  aries_jose.A256GCM,
			cty:     transport.MediaTypeV1PlaintextPayload,
		},
		{
			name:    "anoncrypt using X25519ECDHKWType and AES256-GCM",
			keyType: spikms.X25519ECDHKWType,
			encAlg:  aries_jose.A256GCM,
			cty:     transport.MediaTypeV1PlaintextPayload,
		},
	}

	t.Parallel()

	for _, tt := range tests {
		tc := tt
		t.Run(fmt.Sprintf("running %s", tc.name), func(t *testing.T) {
			t.Logf("anoncrypt packing - creating recipient %s keys...", tc.keyType)
			_, recDIDKeys, recipientsKeys, keyHandles := createRecipientsByKeyType(t, k, 3, tc.keyType)

			cryptoSvc, err := tinkcrypto.New()
			require.NoError(t, err)

			// 构建 JWE Packer
			anonPacker, err := New(newMockProvider(k, cryptoSvc), tc.encAlg)
			require.NoError(t, err)

			// 打包 Envelope
			origMsg := []byte("secret message")
			ct, err := anonPacker.Pack(tc.cty, origMsg, nil, recipientsKeys)
			require.NoError(t, err)

			// 打印 Envelope
			jweStr, err := prettyPrint(ct)
			require.NoError(t, err)
			t.Logf("* anoncrypt JWK: %s", jweStr)

			// 拆包 Envelope
			envelope, err := anonPacker.Unpack(ct)
			require.NoError(t, err)

			// 导出第一个接受者的 Public Key
			recKey, err := exportPubKeyBytes(keyHandles[0], recDIDKeys[0])
			require.NoError(t, err)
			recKeyBytes, err := json.Marshal(recKey)
			require.NoError(t, err)

			// 检查 Envelope
			require.EqualValues(t, &transport.Envelope{Message: origMsg, ToKey: recKeyBytes}, envelope)

			// 使用 jose 包进行拆信封
			jweJSON, err := aries_jose.Deserialize(string(ct))
			require.NoError(t, err)

			// 构建一个接收者的信封
			ct, err = anonPacker.Pack(tc.cty, origMsg, nil, [][]byte{recipientsKeys[0]})
			require.NoError(t, err)
			jweStr, err = prettyPrint(ct)
			require.NoError(t, err)
			t.Logf("* anoncrypt JWE Compact serialization (using first recipient only): %s", jweStr)

			// 使用 jose 包进行拆信封
			jweJSON, err = aries_jose.Deserialize(string(ct))
			require.NoError(t, err)

			// 打包成紧凑模式
			jweStr, err = jweJSON.CompactSerialize(json.Marshal)
			require.NoError(t, err)
			t.Logf("* anoncrypt Flattened JWE JSON serialization (using first recipient only): %s", jweStr)

			// 拆信封
			envelope, err = anonPacker.Unpack(ct)
			require.NoError(t, err)

			require.EqualValues(t, &transport.Envelope{Message: origMsg, ToKey: recKeyBytes}, envelope)
		})
	}
}

func createKMS(t *testing.T) *localkms.LocalKMS {
	t.Helper()

	p, err := mockkms.NewProviderForKMS(
		mockstorage.NewMockStoreProvider(),
		&noop.NoLock{})
	require.NoError(t, err)

	k, err := localkms.New("local-lock://test/key/uri", p)
	require.NoError(t, err)

	return k
}

func newMockProvider(customKMS spikms.KeyManager, customCrypto spicrypto.Crypto) *mockprovider.Provider {
	return &mockprovider.Provider{
		KMSValue:        customKMS,
		CryptoValue:     customCrypto,
		VDRegistryValue: &mockvdr.VDRegistry{},
	}
}

func createRecipientsByKeyType(t *testing.T, k *localkms.LocalKMS, recipientsCount int, kt spikms.KeyType) (
	[]string, []string, [][]byte, []*keyset.Handle) {

	var (
		r       [][]byte
		rKH     []*keyset.Handle
		kids    []string
		didKeys []string
	)

	for i := 0; i < recipientsCount; i++ {
		kid, didKey, marshalledPubKey, kh := createAndMarshalKeyByKeyType(t, k, kt)

		r = append(r, marshalledPubKey)
		rKH = append(rKH, kh)
		kids = append(kids, kid)
		didKeys = append(didKeys, didKey)
	}

	return kids, didKeys, r, rKH
}

func createAndMarshalKeyByKeyType(t *testing.T, k *localkms.LocalKMS,
	kt spikms.KeyType) (string, string, []byte, *keyset.Handle) {
	t.Helper()

	kid, keyHandle, err := k.Create(kt)
	require.NoError(t, err)

	kh, ok := keyHandle.(*keyset.Handle)
	require.True(t, ok)

	pubKey, err := exportPubKeyBytes(kh, kid)
	require.NoError(t, err)

	pubKeyBytes, err := json.Marshal(pubKey)
	require.NoError(t, err)

	didKey, err := kmsdidkey.BuildDIDKeyByKeyType(pubKeyBytes, kt)
	require.NoError(t, err)

	pubKey.KID = didKey
	mKey, err := json.Marshal(pubKey)
	require.NoError(t, err)

	printKey(t, mKey, kh, kid, didKey)

	return kid, didKey, mKey, kh
}

func exportPubKeyBytes(keyHandle *keyset.Handle, kid string) (*spicrypto.PublicKey, error) {
	// 获取 Public Key Handle
	pubKH, err := keyHandle.Public()
	if err != nil {
		return nil, err
	}

	// 导出字节流
	buf := new(bytes.Buffer)
	pubKeyWriter := keyio.NewWriter(buf)

	err = pubKH.WriteWithNoSecrets(pubKeyWriter)
	if err != nil {
		return nil, err
	}

	// 反序列化成 PublicKey 对象
	pubKey := &spicrypto.PublicKey{}
	err = json.Unmarshal(buf.Bytes(), pubKey)
	if err != nil {
		return nil, err
	}

	// 设置 Kid, 重新序列化
	pubKey.KID = kid
	return pubKey, nil
}

type noopAEAD struct{}

func (n noopAEAD) Encrypt(plaintext, _ []byte) ([]byte, error) {
	return plaintext, nil
}

func (n noopAEAD) Decrypt(ciphertext, _ []byte) ([]byte, error) {
	return ciphertext, nil
}

type privKeyWriter struct {
	w io.Writer
}

func (p privKeyWriter) Write(_ *tinkpb.Keyset) error {
	return fmt.Errorf("privKeyWriter: write function not supported")
}

func (p privKeyWriter) WriteEncrypted(ks *tinkpb.EncryptedKeyset) error {
	return write(p.w, ks)
}

func write(w io.Writer, ks *tinkpb.EncryptedKeyset) error {
	_, e := w.Write(ks.EncryptedKeyset)
	return e
}

var _ keyset.Writer = (*privKeyWriter)(nil)

func extractPrivKey(kh *keyset.Handle) (interface{}, error) {
	nistPECDHKWPrivateKeyTypeURL := "type.hyperledger.org/hyperledger.aries.crypto.tink.NistPEcdhKwPrivateKey"
	x25519ECDHKWPrivateKeyTypeURL := "type.hyperledger.org/hyperledger.aries.crypto.tink.X25519EcdhKwPrivateKey"

	buf := new(bytes.Buffer)
	w := &privKeyWriter{w: buf}
	nAEAD := &noopAEAD{}

	if kh == nil {
		return nil, fmt.Errorf("extractPrivKey: kh is nil")
	}

	err := kh.Write(w, nAEAD)
	if err != nil {
		return nil, fmt.Errorf("extractPrivKey: retrieving private key failed: %w", err)
	}

	ks := new(tinkpb.Keyset)
	err = proto.Unmarshal(buf.Bytes(), ks)
	if err != nil {
		return nil, errors.New("extractPrivKey: unmarshal private key failed")
	}

	primaryKey := ks.Key[0]

	switch primaryKey.KeyData.TypeUrl {
	case nistPECDHKWPrivateKeyTypeURL:
		privKey := new(ecdhpb.EcdhAeadPrivateKey)
		err = proto.Unmarshal(primaryKey.KeyData.Value, privKey)
		if err != nil {
			return nil, errors.New("extractPrivKey: invalid private key in keyset")
		}

		var c elliptic.Curve

		c, err = hybrid.GetCurve(privKey.PublicKey.Params.KwParams.CurveType.String())
		if err != nil {
			return nil, fmt.Errorf("extractPrivKey: invalid private key: %w", err)
		}

		return hybrid.GetECPrivateKey(c, privKey.KeyValue), nil

	case x25519ECDHKWPrivateKeyTypeURL:
		privKey := new(ecdhpb.EcdhAeadPrivateKey)

		err = proto.Unmarshal(primaryKey.KeyData.Value, privKey)
		if err != nil {
			return nil, errors.New("extractPrivKey: invalid private key in keyset")
		}

		if privKey.PublicKey.Params.KwParams.CurveType.String() != commonpb.EllipticCurveType_CURVE25519.String() {
			return nil, errors.New("extractPrivKey: invalid private key curve")
		}

		return privKey.KeyValue, nil
	}

	return nil, fmt.Errorf("extractPrivKey: can't extract unsupported private key '%s'", primaryKey.KeyData.TypeUrl)
}

func printKey(t *testing.T, mPubKey []byte, kh *keyset.Handle, kid, didKey string) {
	t.Helper()

	extractKey, err := extractPrivKey(kh)
	require.NoError(t, err)

	switch keyType := extractKey.(type) {
	case *hybrid.ECPrivateKey:
		t.Logf("** EC key: %s, \n\t kms kid: %s, \n\t jwe kid (did:key):%s", getPrintedECPrivKey(t, keyType), kid,
			didKey)
	case []byte:
		pubKey := new(spicrypto.PublicKey)
		err := json.Unmarshal(mPubKey, pubKey)
		require.NoError(t, err)

		fullKey := append(keyType, pubKey.X...)
		t.Logf("** X25519 key: %s, \n\t kms kid: %s, \n\t jwe kid (did:key):%s", getPrintedX25519PrivKey(t, fullKey), kid,
			didKey)
	default:
		t.Errorf("not supported key type: %s", keyType)
	}
}

func getPrintedECPrivKey(t *testing.T, privKey *hybrid.ECPrivateKey) string {
	jwk := jose.JSONWebKey{
		Key: &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: privKey.PublicKey.Curve,
				X:     privKey.PublicKey.Point.X,
				Y:     privKey.PublicKey.Point.Y,
			},
			D: privKey.D,
		},
	}

	jwkBytes, err := jwk.MarshalJSON()
	require.NoError(t, err)

	jwkStr, err := prettyPrint(jwkBytes)
	require.NoError(t, err)

	return jwkStr

}

func getPrintedX25519PrivKey(t *testing.T, privKey ed25519.PrivateKey) string {
	jwk := jose.JSONWebKey{
		Key: privKey,
	}

	jwkBytes, err := jwk.MarshalJSON()
	require.NoError(t, err)

	jwkStr, err := prettyPrint(jwkBytes)
	require.NoError(t, err)

	return strings.Replace(jwkStr, "Ed25519", "X25519", 1)
}

func prettyPrint(msg []byte) (string, error) {
	var prettyJSON bytes.Buffer

	err := json.Indent(&prettyJSON, msg, "", "\t")
	if err != nil {
		return "", err
	}

	return prettyJSON.String(), nil
}
