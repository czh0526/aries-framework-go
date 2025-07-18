package authcrypt

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
	comp_jose "github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/kmsdidkey"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms/localkms"
	comp_mockkms "github.com/czh0526/aries-framework-go/component/kmscrypto/mock/kms"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/secretlock/noop"
	comp_mockstorage "github.com/czh0526/aries-framework-go/component/storage/mock"
	vdrmock "github.com/czh0526/aries-framework-go/component/vdr/mock"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
	doc_jose "github.com/czh0526/aries-framework-go/pkg/doc/jose"
	mockprovider "github.com/czh0526/aries-framework-go/pkg/mock/provider"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"github.com/go-jose/go-jose"
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

func TestAuthCryptPackerSuccess(t *testing.T) {
	k := createKMS(t)

	tests := []struct {
		name    string
		keyType spikms.KeyType
		encAlg  comp_jose.EncAlg
		cty     string
	}{
		{
			name:    "authcrypt using NISTP256ECDHKW and AES128CBC_HMAC_SHA256",
			keyType: spikms.NISTP256ECDHKWType,
			encAlg:  comp_jose.EncAlg(doc_jose.A128CBCHS256ALG),
			cty:     transport.MediaTypeV1PlaintextPayload,
		},
	}

	t.Parallel()

	for _, tt := range tests {
		tc := tt

		t.Run(fmt.Sprintf("running %s", tt.name), func(t *testing.T) {
			t.Logf("authcrypt packing - creating kid %s key...", tc.keyType)
			skid, sDIDKey, mSenderPubKey, kh := createAndMarshalKeyByKeyType(t, k, tt.keyType)
			require.NotEmpty(t, skid)
			require.NotEmpty(t, sDIDKey)
			require.NotEmpty(t, mSenderPubKey)
			require.NotNil(t, kh)

			t.Logf("authcrypt packing - creating recipient %s keys...", tc.keyType)
			_, recDIDKeys, recipientsKeys, keyHandles := createRecipientsByKeyType(t, k, 3, tc.keyType)
			require.NotEmpty(t, recDIDKeys)
			require.NotEmpty(t, recipientsKeys)
			require.NotEmpty(t, keyHandles)

			cryptoSvc, err := tinkcrypto.New()
			require.NoError(t, err)

			authPacker, err := New(newMockProvider(k, cryptoSvc), tc.encAlg)
			require.NoError(t, err)

			origMsg := []byte("secret message")
			ct, err := authPacker.Pack(tc.cty, origMsg, []byte(skid+"."+sDIDKey), recipientsKeys)
			require.NoError(t, err)
			require.NotEmpty(t, ct)
		})
	}
}

func createAndMarshalKeyByKeyType(t *testing.T, kms spikms.KeyManager, kt spikms.KeyType) (
	string, string, []byte, *keyset.Handle) {
	t.Helper()

	kid, keyHandle, err := kms.Create(kt)
	require.NoError(t, err)

	kh, ok := keyHandle.(*keyset.Handle)
	require.True(t, ok)

	pubKeyBytes, err := exportPubKeyBytes(kh, kid)
	require.NoError(t, err)

	key := &spicrypto.PublicKey{}
	err = json.Unmarshal(pubKeyBytes, key)
	require.NoError(t, err)

	didKey, err := kmsdidkey.BuildDIDKeyByKeyType(pubKeyBytes, kt)
	require.NoError(t, err)

	key.KID = didKey
	mKey, err := json.Marshal(key)
	require.NoError(t, err)

	printKey(t, mKey, kh, kid, didKey)

	return kid, didKey, mKey, kh
}

func createRecipientsByKeyType(t *testing.T, k *localkms.LocalKMS,
	recipientsCount int, kt spikms.KeyType) ([]string, []string, [][]byte, []*keyset.Handle) {
	t.Helper()

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

func exportPubKeyBytes(keyHandle *keyset.Handle, kid string) ([]byte, error) {
	pubKH, err := keyHandle.Public()
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	pubKeyWriter := keyio.NewWriter(buf)

	err = pubKH.WriteWithNoSecrets(pubKeyWriter)
	if err != nil {
		return nil, err
	}

	pubKey := &spicrypto.PublicKey{}
	err = json.Unmarshal(buf.Bytes(), pubKey)
	if err != nil {
		return nil, err
	}

	pubKey.KID = kid
	return json.Marshal(pubKey)
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

func prettyPrint(msg []byte) (string, error) {
	var prettyJSON bytes.Buffer

	err := json.Indent(&prettyJSON, msg, "", "\t")
	if err != nil {
		return "", err
	}

	return prettyJSON.String(), nil
}

func getPrintedECPrivKey(t *testing.T, privKeyType *hybrid.ECPrivateKey) string {
	jwk := jose.JSONWebKey{
		Key: &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: privKeyType.PublicKey.Curve,
				X:     privKeyType.PublicKey.Point.X,
				Y:     privKeyType.PublicKey.Point.Y,
			},
			D: privKeyType.D,
		},
	}

	jwkByte, err := jwk.MarshalJSON()
	require.NoError(t, err)

	jwkStr, err := prettyPrint(jwkByte)
	require.NoError(t, err)

	return jwkStr
}

func getPrintedX25519PrivKey(t *testing.T, privKeyType ed25519.PrivateKey) string {
	jwk := jose.JSONWebKey{
		Key: privKeyType,
	}

	jwkByte, err := jwk.MarshalJSON()
	require.NoError(t, err)

	jwkStr, err := prettyPrint(jwkByte)
	require.NoError(t, err)

	return strings.Replace(jwkStr, "ED25519", "X25519", 1)
}

func extractPrivKey(kh *keyset.Handle) (interface{}, error) {
	nistPECDHKWPrivkateKeyTypeURL := "type.hyperledger.org/hyperledger.aries.crypto.tink.NistPEcdhKwPrivateKey"
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
		return nil, errors.New("extractPrivKey: invalid private key")
	}

	primaryKey := ks.Key[0]
	switch primaryKey.KeyData.TypeUrl {
	case nistPECDHKWPrivkateKeyTypeURL:
		pbKey := new(ecdhpb.EcdhAeadPrivateKey)
		err = proto.Unmarshal(primaryKey.KeyData.Value, pbKey)
		if err != nil {
			return nil, errors.New("extractPrivKey: invalid private key in keyset")
		}

		var c elliptic.Curve
		c, err = hybrid.GetCurve(pbKey.PublicKey.Params.KwParams.CurveType.String())
		if err != nil {
			return nil, fmt.Errorf("extractPrivKey: invalid key: %w", err)
		}

		return hybrid.GetECPrivateKey(c, pbKey.KeyValue), nil

	case x25519ECDHKWPrivateKeyTypeURL:
		pbKey := new(ecdhpb.EcdhAeadPrivateKey)

		err = proto.Unmarshal(primaryKey.KeyData.Value, pbKey)
		if err != nil {
			return nil, errors.New("extractPrivKey: invalid key in keyset")
		}

		if pbKey.PublicKey.Params.KwParams.CurveType.String() != commonpb.EllipticCurveType_CURVE25519.String() {
			return nil, errors.New("extractPrivKey: invalid key curve")
		}

		return pbKey.KeyValue, nil
	}

	return nil, fmt.Errorf("extractPrivKey: can't extract unsupported private key '%s'", primaryKey.KeyData.TypeUrl)
}

type privKeyWriter struct {
	w io.Writer
}

func (p privKeyWriter) Write(_ *tinkpb.Keyset) error {
	return fmt.Errorf("privKeyWriter: write function not support")
}

func (p privKeyWriter) WriteEncrypted(ks *tinkpb.EncryptedKeyset) error {
	return write(p.w, ks)
}

func write(w io.Writer, ks *tinkpb.EncryptedKeyset) error {
	_, e := w.Write(ks.EncryptedKeyset)
	return e
}

type noopAEAD struct{}

func (n noopAEAD) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	return plaintext, nil
}

func (n noopAEAD) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	return ciphertext, nil
}

func createKMS(t *testing.T) *localkms.LocalKMS {
	t.Helper()

	kmsProvider, err := comp_mockkms.NewProviderForKMS(
		comp_mockstorage.NewMockStoreProvider(),
		&noop.NoLock{},
	)
	require.NoError(t, err)

	kms, err := localkms.New("local-lock://test/uri", kmsProvider)
	require.NoError(t, err)

	return kms
}

func newMockProvider(customKMS spikms.KeyManager,
	customCrypto spicrypto.Crypto) *mockprovider.Provider {
	return &mockprovider.Provider{
		KMSValue:        customKMS,
		CryptoValue:     customCrypto,
		VDRegistryValue: &vdrmock.VDRegistry{},
	}
}
