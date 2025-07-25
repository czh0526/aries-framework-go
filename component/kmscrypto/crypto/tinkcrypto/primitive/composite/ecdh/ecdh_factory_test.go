package ecdh

import (
	"encoding/base64"
	"encoding/json"
	ecdhpb "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
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
	c := commonpb.EllipticCurveType_NIST_P256
	primaryPtFmt := commonpb.EcPointFormat_UNCOMPRESSED
	primaryEncT := aead.AES128GCMKeyTemplate()
	rawPtFmt := commonpb.EcPointFormat_COMPRESSED
	rawEncT := aead.AES256GCMKeyTemplate()
	kt := ecdhpb.KeyType_EC
	cek := random.GetRandomBytes(32)

	primaryPrivProto := generateECDHAEADPrivateKey(t, c, primaryPtFmt, kt, primaryEncT, cek)
	sPrimaryPriv, err := proto.Marshal(primaryPrivProto)
	require.NoError(t, err)
	primaryPrivKey := testutil.NewKey(
		testutil.NewKeyData(nistpECDHKWPrivateKeyTypeURL, sPrimaryPriv, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
		tinkpb.KeyStatusType_ENABLED, 8, tinkpb.OutputPrefixType_RAW)

	rawPrivProto := generateECDHAEADPrivateKey(t, c, rawPtFmt, kt, rawEncT, cek)
	sRawPriv, err := proto.Marshal(rawPrivProto)
	require.NoError(t, err)
	rawPrivKey := testutil.NewKey(
		testutil.NewKeyData(nistpECDHKWPrivateKeyTypeURL, sRawPriv, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
		tinkpb.KeyStatusType_ENABLED, 11, tinkpb.OutputPrefixType_RAW)

	privKeys := []*tinkpb.Keyset_Key{primaryPrivKey, rawPrivKey}
	privKeyset := testutil.NewKeyset(privKeys[0].KeyId, privKeys)
	khPriv, err := testkeyset.NewHandle(privKeyset)

	khPub, err := khPriv.Public()
	require.NoError(t, err)

	e, err := NewECDHEncrypt(khPub)
	require.NoError(t, err)

	d, err := NewECDHDecrypt(khPriv)
	require.NoError(t, err)

	for i := 0; i < 4; i++ {
		pt := random.GetRandomBytes(32)
		aadRndNb := random.GetRandomBytes(10)

		aadJSON, err := json.Marshal(aadRndNb)
		require.NoError(t, err)

		aad, err := json.Marshal(&map[string]interface{}{"someFiled": json.RawMessage(aadJSON)})
		require.NoError(t, err)

		aadStr := base64.StdEncoding.EncodeToString(aad)
		aad = []byte(aadStr)

		ct, err := e.Encrypt(pt, aad)
		require.NoError(t, err)

		gotpt, err := d.Decrypt(ct, aad)
		require.NoError(t, err)

		require.EqualValues(t, pt, gotpt)
	}
}

func generateECDHAEADPrivateKey(t *testing.T, c commonpb.EllipticCurveType, ptfmt commonpb.EcPointFormat,
	kt ecdhpb.KeyType, encT *tinkpb.KeyTemplate, cek []byte) *ecdhpb.EcdhAeadPrivateKey {
	t.Helper()

	curve, err := hybrid.GetCurve(c.String())
	require.NoError(t, err)

	pvt, err := hybrid.GenerateECDHKeyPair(curve)
	require.NoError(t, err)

	point := pvt.PublicKey.Point
	pubKey := ecdhAEADPublicKey(t, c, ptfmt, kt, encT, point.X.Bytes(), point.Y.Bytes(), cek)

	return ecdhesAEADPrivateKey(t, pubKey, pvt.D.Bytes())
}

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

func ecdhesAEADPrivateKey(t *testing.T, pubKey *ecdhpb.EcdhAeadPublicKey, d []byte) *ecdhpb.EcdhAeadPrivateKey {
	t.Helper()

	return &ecdhpb.EcdhAeadPrivateKey{
		Version:   0,
		PublicKey: pubKey,
		KeyValue:  d,
	}
}
