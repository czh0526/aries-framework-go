package secp256k1

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	secp256k1pb "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/secp256k1_go_proto"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/secp256k1/subtle"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"
)

const (
	secp256k1SignerKeyVersion = uint32(0)
	secp256k1SignerTypeURL    = "type.hyperledger.org/hyperledger.aries.crypto.tink.secp256k1PrivateKey"
)

var (
	errInvalidSECP256K1SignKey       = errors.New("secp256k1_signer_key_manager: invalid key")
	errInvalidSECP256K1SignKeyFormat = errors.New("secp256k1_signer_key_manager: invalid key format")
)

type secp256k1SignerKeyManager struct {
}

func (km *secp256k1SignerKeyManager) Primitive(serializedKey []byte) (any, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidSECP256K1SignKey
	}

	key := new(secp256k1pb.Secp256K1PrivateKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, errInvalidSECP256K1SignKey
	}

	if err := km.validateKey(key); err != nil {
		return nil, err
	}

	hash, curve, encoding := getSecp256K1ParamNames(key.PublicKey.Params)
	ret, err := subtle.NewSecp256K1Signer(hash, curve, encoding, key.KeyValue)
	if err != nil {
		return nil, fmt.Errorf("secp256k1_signer_key_manager: %w", err)
	}

	return ret, nil
}

// NewKey create ECDSAPrivateKey from ECDSAKeyFormat
func (km *secp256k1SignerKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidSECP256K1SignKeyFormat
	}

	keyFormat := new(secp256k1pb.Secp256K1KeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, fmt.Errorf("secp256k1_signer_key_manager: invalid proto: %w", err)
	}

	if err := km.validateKeyFormat(keyFormat); err != nil {
		return nil, fmt.Errorf("secp256k1_signer_key_manager: invalid key format: %w", err)
	}

	params := keyFormat.Params
	tmpKey, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("secp256k1_signer_key_manager: failed to generate ECDSA key: %w", err)
	}

	keyValue := tmpKey.D.Bytes()
	pub := newSecp256K1PublicKey(secp256k1SignerKeyVersion, params, tmpKey.X.Bytes(), tmpKey.Y.Bytes())
	priv := newSecp256K1PrivateKey(secp256k1SignerKeyVersion, pub, keyValue)

	return priv, nil
}

func (km *secp256k1SignerKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == secp256k1SignerTypeURL
}

func (km *secp256k1SignerKeyManager) TypeURL() string {
	return secp256k1SignerTypeURL
}

func (km *secp256k1SignerKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}

	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, errInvalidSECP256K1SignKeyFormat
	}

	return &tinkpb.KeyData{
		TypeUrl:         secp256k1SignerTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

func (km *secp256k1SignerKeyManager) PublicKeyData(serializedPrivKey []byte) (*tinkpb.KeyData, error) {
	privKey := new(secp256k1pb.Secp256K1PrivateKey)
	if err := proto.Unmarshal(serializedPrivKey, privKey); err != nil {
		return nil, err
	}

	serializedPubKey, err := proto.Marshal(privKey.PublicKey)
	if err != nil {
		return nil, errInvalidSECP256K1SignKey
	}

	return &tinkpb.KeyData{
		TypeUrl:         secp256k1VerifierKeyTypeURL,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

func (km *secp256k1SignerKeyManager) validateKey(key *secp256k1pb.Secp256K1PrivateKey) error {
	return nil
}

func (km *secp256k1SignerKeyManager) validateKeyFormat(format *secp256k1pb.Secp256K1KeyFormat) error {
	return nil
}

func newSecp256K2SignerKeyManager() *secp256k1SignerKeyManager {
	return new(secp256k1SignerKeyManager)
}

func getSecp256K1ParamNames(params *secp256k1pb.Secp256K1Params) (string, string, string) {
	hashName := commonpb.HashType_name[int32(params.HashType)]
	curveName := secp256k1pb.BitcoinCurveType_name[int32(params.Curve)]
	encodingName := secp256k1pb.Secp256K1SignatureEncoding_name[int32(params.Encoding)]

	return hashName, curveName, encodingName
}

func ValidateSecp256K1Params(hashAlg, curve, encoding string) error {
	switch encoding {
	case "Bitcoin_DER":
	case "Bitcoin_IEEE_P1363":
	default:
		return errors.New("secp256k1: unsupported encoding")
	}

	switch curve {
	case "SECP256K1":
		if hashAlg != "SHA256" {
			return errors.New("invalid hash type for secp256k1 curve, expect `SHA256`")
		}
	default:
		return fmt.Errorf("unsupported curve: %s", curve)
	}

	return nil
}

func newSecp256K1PublicKey(version uint32,
	params *secp256k1pb.Secp256K1Params,
	x, y []byte) *secp256k1pb.Secp256K1PublicKey {

	return &secp256k1pb.Secp256K1PublicKey{
		Version: version,
		Params:  params,
		X:       x,
		Y:       y,
	}
}
func newSecp256K1PrivateKey(version uint32,
	publicKey *secp256k1pb.Secp256K1PublicKey,
	keyValue []byte) *secp256k1pb.Secp256K1PrivateKey {

	return &secp256k1pb.Secp256K1PrivateKey{
		Version:   version,
		PublicKey: publicKey,
		KeyValue:  keyValue,
	}
}
