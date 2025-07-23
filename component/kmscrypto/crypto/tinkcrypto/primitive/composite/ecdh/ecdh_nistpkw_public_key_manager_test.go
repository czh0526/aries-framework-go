package ecdh

import (
	"crypto/elliptic"
	"crypto/rand"
	cbcaead "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite"
	ecdhpb "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
	"github.com/stretchr/testify/require"
	"github.com/tink-crypto/tink-go/v2/aead"
	hybridsubtle "github.com/tink-crypto/tink-go/v2/hybrid/subtle"
	gcmpb "github.com/tink-crypto/tink-go/v2/proto/aes_gcm_go_proto"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"
	"strings"
	"testing"
)

func TestECDHNISTPAESPublicKeyManager_Primitive(t *testing.T) {
	km := newECDHNISTPAESPublicKeyManager()

	t.Run("Test publiv key manager Primitive() with empty serialized key", func(t *testing.T) {
		p, err := km.Primitive([]byte(""))
		require.EqualError(t, err, errInvalidNISTPECDHKWPublicKey.Error(),
			"newECDHNISTPAESPublicKeyManager() primitive from empty serialized key must fail")
		require.Empty(t, p)
	})

	t.Run("Test publiv key manager Primitive() with bad serialized key", func(t *testing.T) {
		p, err := km.Primitive([]byte("bad.data"))
		require.EqualError(t, err, errInvalidNISTPECDHKWPublicKey.Error(),
			"newECDHNISTPAESPublicKeyManager() primitive from bad serialized key must fail")
		require.Empty(t, p)
	})

	format := &gcmpb.AesGcmKeyFormat{
		KeySize: 32,
	}
	serializedFormat, err := proto.Marshal(format)
	require.NoError(t, err)

	format = &gcmpb.AesGcmKeyFormat{
		KeySize: 99,
	}
	badSerializedFormat, err := proto.Marshal(format)
	require.NoError(t, err)

	flagTests := []struct {
		tcName    string
		version   uint32
		curveType commonpb.EllipticCurveType
		ecPtFmt   commonpb.EcPointFormat
		encTmp    *tinkpb.KeyTemplate
	}{
		{
			tcName:    "public key manager Primitive() using key with bad version",
			version:   9999,
			curveType: commonpb.EllipticCurveType_NIST_P256,
			ecPtFmt:   commonpb.EcPointFormat_COMPRESSED,
			encTmp:    aead.AES128GCMKeyTemplate(),
		},
		{
			tcName:    "public key manager Primitive() using key with bad curve",
			version:   0,
			curveType: commonpb.EllipticCurveType_UNKNOWN_CURVE,
			ecPtFmt:   commonpb.EcPointFormat_COMPRESSED,
			encTmp:    aead.AES128GCMKeyTemplate(),
		},
		{
			tcName:    "success public key manager Primitive()",
			version:   0,
			curveType: commonpb.EllipticCurveType_NIST_P256,
			ecPtFmt:   commonpb.EcPointFormat_COMPRESSED,
			encTmp:    aead.AES128GCMKeyTemplate(),
		},
		{
			tcName:    "public key manager Primitive() using key with bad key template URL",
			version:   0,
			curveType: commonpb.EllipticCurveType_NIST_P256,
			ecPtFmt:   commonpb.EcPointFormat_COMPRESSED,
			encTmp: &tinkpb.KeyTemplate{
				TypeUrl:          "bad.type/url/value",
				Value:            serializedFormat,
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
		{
			tcName:    "public key manager Primitive() using key with bad content encryption key size",
			version:   0,
			curveType: commonpb.EllipticCurveType_NIST_P256,
			ecPtFmt:   commonpb.EcPointFormat_COMPRESSED,
			encTmp: &tinkpb.KeyTemplate{
				TypeUrl:          composite.AESGCMTypeURL,
				Value:            badSerializedFormat,
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
		{
			tcName:    "success public key manager Primitive() with AES-CBC+HMAC encTmp",
			version:   0,
			curveType: commonpb.EllipticCurveType_NIST_P256,
			ecPtFmt:   commonpb.EcPointFormat_UNCOMPRESSED,
			encTmp:    cbcaead.AES128CBCHMACSHA256KeyTemplate(),
		},
	}

	for _, tc := range flagTests {
		tt := tc
		t.Run("Test "+tt.tcName, func(t *testing.T) {
			c := tt.curveType
			encT := tt.encTmp
			ptFmt := tt.ecPtFmt
			v := tt.version

			if tt.curveType.String() == commonpb.EllipticCurveType_UNKNOWN_CURVE.String() {
				c = commonpb.EllipticCurveType_NIST_P256
			}

			crv, err := hybridsubtle.GetCurve(c.String())
			require.NoError(t, err)
			_, x, y, err := elliptic.GenerateKey(crv, rand.Reader)
			require.NoError(t, err)

			if tt.curveType.String() == commonpb.EllipticCurveType_UNKNOWN_CURVE.String() {
				c = tt.curveType
			}

			pubKeyProto := &ecdhpb.EcdhAeadPublicKey{
				Version: v,
				Params: &ecdhpb.EcdhAeadParams{
					KwParams: &ecdhpb.EcdhKwParams{
						CurveType: c,
						KeyType:   ecdhpb.KeyType_EC,
					},
					EncParams: &ecdhpb.EcdhAeadEncParams{
						AeadEnc: encT,
					},
					EcPointFormat: ptFmt,
				},
				X: x.Bytes(),
				Y: y.Bytes(),
			}

			sPubKey, err := proto.Marshal(pubKeyProto)
			require.NoError(t, err)

			p, err := km.Primitive(sPubKey)
			if strings.Contains(tt.tcName, "with bad content encryption key size") {
				require.EqualError(t, err, errInvalidNISTPECDHKWPublicKey.Error(),
					"newECDHNISTPAESPublicKeyManager() primitive from serialized key with invali serialized key")
				require.Empty(t, p)
				return
			}

			if strings.Contains(tt.tcName, "success") {
				require.NoError(t, err)
				require.NotEmpty(t, p)
				return
			}

			require.Error(t, err, tt.tcName)
			require.Empty(t, p)
		})
	}
}
