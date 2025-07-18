package secp256k1

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	secp256k1pb "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/secp256k1_go_proto"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/secp256k1/subtle"
	"github.com/stretchr/testify/require"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	"google.golang.org/protobuf/proto"
	"math/big"
	"testing"
)

type secp256k1Params struct {
	hashType commonpb.HashType
	curve    secp256k1pb.BitcoinCurveType
}

func TestSecp256k1Signer_Primitive(t *testing.T) {

	// 构造一个 secp256k1 private key
	privateKey, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	require.NoError(t, err)

	// 构造一个 KMS public Key
	params := NewSecp256K1Params(
		commonpb.HashType_SHA256,
		secp256k1pb.BitcoinCurveType_SECP256K1,
		secp256k1pb.Secp256K1SignatureEncoding_Bitcoin_DER)
	kmsPublicKey := newSecp256K1PublicKey(
		secp256k1SignerKeyVersion,
		params,
		privateKey.X.Bytes(), privateKey.Y.Bytes())

	// 构造一个 KMS private Key
	kmsPrivateKey := newSecp256K1PrivateKey(
		secp256k1SignerKeyVersion, kmsPublicKey, privateKey.D.Bytes())

	// 构造一个 serialized Key
	serializedKey, err := proto.Marshal(kmsPrivateKey)
	require.NoError(t, err)

	// 构造一个 KeyManager
	km, err := registry.GetKeyManager(secp256k1SignerTypeURL)
	require.NoError(t, err)

	// 测试 Primitive 函数， 返回一个 Key
	key, err := km.Primitive(serializedKey)
	require.NoError(t, err)

	// 测试 Key 是否和打包前一致
	_, ok := key.(*subtle.Secp256K1Signer)
	require.True(t, ok)
}

func TestSecp256k1Singer_NewKey(t *testing.T) {

	km, err := registry.GetKeyManager(secp256k1SignerTypeURL)
	require.NoError(t, err)

	keyParams := &secp256k1pb.Secp256K1Params{
		HashType: commonpb.HashType_SHA256,
		Curve:    secp256k1pb.BitcoinCurveType_SECP256K1,
		Encoding: secp256k1pb.Secp256K1SignatureEncoding_Bitcoin_DER,
	}
	serializedKeyFormat, err := proto.Marshal(&secp256k1pb.Secp256K1KeyFormat{
		Params: keyParams,
	})
	require.NoError(t, err)

	// 测试 NewKey 函数
	tmp, err := km.NewKey(serializedKeyFormat)
	require.NoError(t, err)

	key, ok := tmp.(*secp256k1pb.Secp256K1PrivateKey)
	require.True(t, ok)

	err = validateECDSASecp256K1PrivateKey(t, key, keyParams)
	require.NoError(t, err)
}

func TestSecp256K1Sign_NewKeyData(t *testing.T) {

	km, err := registry.GetKeyManager(secp256k1SignerTypeURL)
	require.NoError(t, err)

	keyParams := &secp256k1pb.Secp256K1Params{
		HashType: commonpb.HashType_SHA256,
		Curve:    secp256k1pb.BitcoinCurveType_SECP256K1,
		Encoding: secp256k1pb.Secp256K1SignatureEncoding_Bitcoin_DER,
	}
	serializedKeyFormat, err := proto.Marshal(&secp256k1pb.Secp256K1KeyFormat{
		Params: keyParams,
	})
	require.NoError(t, err)

	// 测试 NewKeyData 函数
	keyData, err := km.NewKeyData(serializedKeyFormat)
	require.NoError(t, err)

	key := &secp256k1pb.Secp256K1PrivateKey{}
	err = proto.Unmarshal(keyData.Value, key)
	require.NoError(t, err)

	err = validateECDSASecp256K1PrivateKey(t, key, keyParams)
	require.NoError(t, err)

}

func genValidSecp256k1Params() []secp256k1Params {
	return []secp256k1Params{
		{
			hashType: commonpb.HashType_SHA256,
			curve:    secp256k1pb.BitcoinCurveType_SECP256K1,
		},
	}
}

func NewSecp256K1Params(hashType commonpb.HashType,
	curve secp256k1pb.BitcoinCurveType,
	encoding secp256k1pb.Secp256K1SignatureEncoding) *secp256k1pb.Secp256K1Params {
	return &secp256k1pb.Secp256K1Params{
		HashType: hashType,
		Curve:    curve,
		Encoding: encoding,
	}
}

func NewRandomSecp256K1PrivateKey(hashType commonpb.HashType,
	curve secp256k1pb.BitcoinCurveType) *secp256k1pb.Secp256K1PrivateKey {

	// curve encoding --> curve name
	curveName := secp256k1pb.BitcoinCurveType_name[int32(curve)]
	if curveName == secp256k1pb.BitcoinCurveType_INVALID_BITCOIN_CURVE.String() {
		return nil
	}

	// curve name --> elliptic curve
	priv, err := ecdsa.GenerateKey(subtle.GetCurve(curveName), rand.Reader)
	if err != nil {
		return nil
	}

	// pack public key
	params := NewSecp256K1Params(hashType, curve, secp256k1pb.Secp256K1SignatureEncoding_Bitcoin_DER)
	publicKey := newSecp256K1PublicKey(secp256k1SignerKeyVersion, params, priv.X.Bytes(), priv.Y.Bytes())

	// pack private key
	return newSecp256K1PrivateKey(secp256k1SignerKeyVersion, publicKey, priv.D.Bytes())
}

var errSmallKey = fmt.Errorf("private key doesn't have adequate size")

func validateECDSASecp256K1PrivateKey(t *testing.T,
	key *secp256k1pb.Secp256K1PrivateKey,
	params *secp256k1pb.Secp256K1Params) error {

	require.Equalf(t, key.Version, secp256k1SignerKeyVersion, "invalid private key version")

	publicKey := key.PublicKey
	require.Equalf(t, publicKey.Version, secp256k1SignerKeyVersion, "invalid public key version")

	if params.HashType != publicKey.Params.HashType ||
		params.Curve != publicKey.Params.Curve ||
		params.Encoding != publicKey.Params.Encoding {
		return fmt.Errorf("incorrect params: expect %s, got %s", params, publicKey.Params)
	}

	if len(publicKey.X) == 0 || len(publicKey.Y) == 0 {
		return fmt.Errorf("public points are not initialized")
	}

	d := new(big.Int).SetBytes(key.KeyValue)
	keySize := len(d.Bytes())

	if params.Curve == secp256k1pb.BitcoinCurveType_SECP256K1 {
		if keySize < 256/8-8 || keySize > 256/8+1 {
			return errSmallKey
		}
	}

	hash, curve, encoding := getSecp256K1ParamNames(params)
	signer, err := subtle.NewSecp256K1Signer(hash, curve, encoding, key.KeyValue)
	require.NoError(t, err, "unexpected error when creating secp256k1 signer")
	require.NotEmpty(t, signer, "failed to create secp256k1 signer")

	return nil
}
