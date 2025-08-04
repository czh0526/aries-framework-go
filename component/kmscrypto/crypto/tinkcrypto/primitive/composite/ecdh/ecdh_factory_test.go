package ecdh

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	ecdhpb "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/util/cryptoutil"
	"github.com/stretchr/testify/require"
	"github.com/tink-crypto/tink-go/v2/aead"
	hybrid "github.com/tink-crypto/tink-go/v2/hybrid/subtle"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"github.com/tink-crypto/tink-go/v2/testkeyset"
	"github.com/tink-crypto/tink-go/v2/testutil"
	"google.golang.org/protobuf/proto"
	"testing"
)

func TestECDHESFactory(t *testing.T) {
	//c := commonpb.EllipticCurveType_NIST_P256
	primaryPtFmt := commonpb.EcPointFormat_UNCOMPRESSED
	//primaryEncT := aead.AES128GCMKeyTemplate()
	//rawPtFmt := commonpb.EcPointFormat_COMPRESSED
	//rawEncT := aead.AES256GCMKeyTemplate()
	//kt := ecdhpb.KeyType_EC
	cek := random.GetRandomBytes(32)

	//// 构建 EC_P256 + AES_128 + EC 的密钥
	//primaryPrivProto := generateECDHAEADPrivateKey(t, c, primaryPtFmt, kt, primaryEncT, cek)
	//sPrimaryPriv, err := proto.Marshal(primaryPrivProto)
	//require.NoError(t, err)
	//primaryPrivKey := testutil.NewKey(
	//	testutil.NewKeyData(nistpECDHKWPrivateKeyTypeURL, sPrimaryPriv, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
	//	tinkpb.KeyStatusType_ENABLED, 8, tinkpb.OutputPrefixType_RAW)
	//
	//// 构建 EC_P256 + AES_256 + EC 的密钥
	//rawPrivProto := generateECDHAEADPrivateKey(t, c, rawPtFmt, kt, rawEncT, cek)
	//sRawPriv, err := proto.Marshal(rawPrivProto)
	//require.NoError(t, err)
	//rawPrivKey := testutil.NewKey(
	//	testutil.NewKeyData(nistpECDHKWPrivateKeyTypeURL, sRawPriv, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
	//	tinkpb.KeyStatusType_ENABLED, 11, tinkpb.OutputPrefixType_RAW)

	// 构建 X25519 + AES_256 + OKP 的密钥
	x25519XChachaPrivProto := generateECDHAEADPrivateKey(t, commonpb.EllipticCurveType_CURVE25519,
		primaryPtFmt, ecdhpb.KeyType_OKP, aead.XChaCha20Poly1305KeyTemplate(), cek)
	sX25519XChachaPriv, err := proto.Marshal(x25519XChachaPrivProto)
	require.NoError(t, err)
	x25519XChachaPrivKey := testutil.NewKey(
		testutil.NewKeyData(x25519ECDHKWPrivateKeyTypeURL, sX25519XChachaPriv, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
		tinkpb.KeyStatusType_ENABLED, 15, tinkpb.OutputPrefixType_RAW)

	// 构建 keys => keyset => key handle
	privKeys := []*tinkpb.Keyset_Key{ /* primaryPrivKey, rawPrivKey, */ x25519XChachaPrivKey}
	privKeyset := testutil.NewKeyset(privKeys[0].KeyId, privKeys)

	khPriv, err := testkeyset.NewHandle(privKeyset)
	khPub, err := khPriv.Public()
	require.NoError(t, err)

	e, err := NewECDHCrypto(khPub)
	require.NoError(t, err)
	d, err := NewECDHCrypto(khPriv)
	require.NoError(t, err)

	for i := 0; i < 4; i++ {
		pt := random.GetRandomBytes(32)
		//pt := []byte("这是一条测试消息！")
		aadRndNb := random.GetRandomBytes(10)

		aadValue, err := json.Marshal(aadRndNb)
		require.NoError(t, err)

		aadJSON, err := json.Marshal(&map[string]interface{}{"someField": json.RawMessage(aadValue)})
		require.NoError(t, err)

		aadStr := base64.StdEncoding.EncodeToString(aadJSON)
		aad := []byte(aadStr)

		ct, err := e.Encrypt(pt, aad)
		require.NoError(t, err)

		gotpt, err := e.Decrypt(ct, aad)
		require.NoError(t, err)

		gotpt, err = d.Decrypt(ct, aad)
		require.NoError(t, err)

		require.EqualValues(t, pt, gotpt)
	}
}

// generateECDHAEADPrivateKey 随机生成一个 ECDH AEAD 的私钥
func generateECDHAEADPrivateKey(t *testing.T, c commonpb.EllipticCurveType,
	ptfmt commonpb.EcPointFormat, kt ecdhpb.KeyType,
	encT *tinkpb.KeyTemplate, cek []byte) *ecdhpb.EcdhAeadPrivateKey {
	t.Helper()

	if ecdhpb.KeyType_OKP.String() == kt.String() {
		return buildXChachaKey(t, ptfmt, encT, c, cek)
	}

	// 获取椭圆曲线
	curve, err := hybrid.GetCurve(c.String())
	require.NoError(t, err)

	// 产生密钥对
	pvt, err := hybrid.GenerateECDHKeyPair(curve)
	require.NoError(t, err)

	// 构建 ECDH AEAD 公钥
	point := pvt.PublicKey.Point
	pubKey := ecdhAEADPublicKey(t, c, ptfmt, kt, encT, point.X.Bytes(), point.Y.Bytes(), cek)

	// 构造 ECDH AEAD 私钥
	return ecdhesAEADPrivateKey(t, pubKey, pvt.D.Bytes())
}

// ecdhAEADPublicKey 构造 ECDH AEAD 的公钥
func ecdhAEADPublicKey(t *testing.T, c commonpb.EllipticCurveType, ptfmt commonpb.EcPointFormat,
	kt ecdhpb.KeyType, encT *tinkpb.KeyTemplate, x, y, cek []byte) *ecdhpb.EcdhAeadPublicKey {
	t.Helper()

	return &ecdhpb.EcdhAeadPublicKey{
		Version: 0,
		Params: &ecdhpb.EcdhAeadParams{
			KwParams: &ecdhpb.EcdhKwParams{
				CurveType: c,
				KeyType:   kt,
			},
			EncParams: &ecdhpb.EcdhAeadEncParams{
				AeadEnc: encT,
				CEK:     cek,
			},
			EcPointFormat: ptfmt,
		},
		X: x,
		Y: y,
	}
}

// ecdhesAEADPrivateKey 构造 ECDH AEAD 私钥
func ecdhesAEADPrivateKey(t *testing.T, pubKey *ecdhpb.EcdhAeadPublicKey, d []byte) *ecdhpb.EcdhAeadPrivateKey {
	t.Helper()

	return &ecdhpb.EcdhAeadPrivateKey{
		Version:   0,
		PublicKey: pubKey,
		KeyValue:  d,
	}
}

func buildXChachaKey(t *testing.T, ptfmt commonpb.EcPointFormat, encT *tinkpb.KeyTemplate,
	c commonpb.EllipticCurveType, cek []byte) *ecdhpb.EcdhAeadPrivateKey {

	pub, pvt, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	x25519Pub, err := cryptoutil.PublicEd25519toCurve25519(pub)
	require.NoError(t, err)

	x25519Pvt, err := cryptoutil.SecretEd25519toCurve25519(pvt)
	require.NoError(t, err)

	params := &ecdhpb.EcdhAeadParams{
		KwParams: &ecdhpb.EcdhKwParams{
			KeyType:   ecdhpb.KeyType_OKP,
			CurveType: c,
		},
		EncParams: &ecdhpb.EcdhAeadEncParams{
			AeadEnc: encT,
			CEK:     cek,
		},
		EcPointFormat: ptfmt,
	}

	return &ecdhpb.EcdhAeadPrivateKey{
		Version:  0,
		KeyValue: x25519Pvt,
		PublicKey: &ecdhpb.EcdhAeadPublicKey{
			Version: 0,
			Params:  params,
			X:       x25519Pub,
		},
	}
}
