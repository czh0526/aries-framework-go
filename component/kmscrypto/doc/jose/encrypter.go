package jose

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead/subtle"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/ecdh"
	ecdhpb "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/util/cryptoutil"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	"github.com/go-jose/go-jose/v3"
	hybrid "github.com/tink-crypto/tink-go/v2/hybrid/subtle"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"golang.org/x/crypto/curve25519"
	"math/big"
	"sort"
	"strings"
)

type EncAlg string

const (
	A256GCM      = EncAlg(A256GCMALG)
	XC20P        = EncAlg(XC20PALG)
	A128CBCHS256 = EncAlg(A128CBCHS256ALG)
	A192CBCHS384 = EncAlg(A192CBCHS384ALG)
	A256CBCHS384 = EncAlg(A256CBCHS384ALG)
	A256CBCHS512 = EncAlg(A256CBCHS512ALG)
)

type EncEncrypter interface {
	EncryptWithAuthData(plaintext, aad []byte) (*JSONWebEncryption, error)

	Encrypt(plaintext []byte) (*JSONWebEncryption, error)
}

type JWEEncrypt struct {
	recipientsKeys []*spicrypto.PublicKey
	skid           string
	senderKH       *keyset.Handle
	encAlg         EncAlg
	encTyp         string
	cty            string
	crypto         spicrypto.Crypto
}

func (je *JWEEncrypt) Encrypt(plaintext []byte) (*JSONWebEncryption, error) {
	return je.EncryptWithAuthData(plaintext, nil)
}

func (je *JWEEncrypt) EncryptWithAuthData(plaintext, aad []byte) (*JSONWebEncryption, error) {
	protectedHeaders := map[string]interface{}{
		HeaderEncryption: je.encAlg,
		HeaderType:       je.encTyp,
	}
	je.addExtraProtectedHeaders(protectedHeaders)

	cek := je.newCEK()

	encPrimitive, err := je.getECDHEncPrimitive(cek)
	if err != nil {
		return nil, fmt.Errorf("jweencrypt: failed to get encryption primitive: %w", err)
	}

	authData, err := computeAuthData(protectedHeaders, "", aad)
	if err != nil {
		return nil, fmt.Errorf("jweencrypt: computeAuthData: marshal error %w", err)
	}

	if je.senderKH != nil && je.skid != "" {
		return je.encryptWithSender(encPrimitive, plaintext, authData, cek, aad)
	}

	return je.encrypt(protectedHeaders, encPrimitive, plaintext, authData, cek, aad)
}

func (je *JWEEncrypt) encryptWithSender(primitive api.CompositeEncrypt,
	plaintext, authData, cek, aad []byte) (*JSONWebEncryption, error) {

	apu, apv, err := je.buildAPUAPV()
	if err != nil {
		return nil, fmt.Errorf("jweencryptWithSender: %w", err)
	}

	epk, authData, newProtectedHeaders, err := je.generateEPKAndUpdateAuthDataFor1PU(
		authData, cek, apu, apv)
	if err != nil {
		return nil, fmt.Errorf("jweencryptWithSender: %w", err)
	}

	serializedEncData, err := primitive.Encrypt(plaintext, authData)
	if err != nil {
		return nil, fmt.Errorf("jweencryptWithSender: failed to Encrypt: %w", err)
	}

	encData := new(composite.EncryptedData)

	err = json.Unmarshal(serializedEncData, encData)
	if err != nil {
		return nil, fmt.Errorf("jweencryptWithSender: unmarshal encrypted data failed: %w", err)
	}
}

func (je *JWEEncrypt) buildAPUAPV() ([]byte, []byte, error) {
	if je.skid == "" {
		return nil, nil, fmt.Errorf("cannot create APU/APV with empty sender skid")
	}

	if len(je.recipientsKeys) == 0 {
		return nil, nil, fmt.Errorf("cannot create APU/APV with empty recipient keys")
	}

	var recKIDs []string

	apu := make([]byte, len(je.skid))
	copy(apu, je.skid)

	for _, r := range je.recipientsKeys {
		recKIDs = append(recKIDs, r.KID)
	}

	// set recipients' sorted kids list then SHA256 hashed in apv.
	sort.Strings(recKIDs)

	apvList := []byte(strings.Join(recKIDs, "."))
	apv32 := sha256.Sum256(apvList)
	apv := make([]byte, 32)
	copy(apv, apv32[:])

	return apu, apv, nil
}

func (je *JWEEncrypt) generateEPKAndUpdateAuthDataFor1PU(auth, cek, apu, apv []byte) (
	*spicrypto.PrivateKey, []byte, map[string]interface{}, error) {
	var epk *spicrypto.PrivateKey

	epk, kwAlg, err := je.newEPK(cek)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("jweencrypt: generateEPKAndUpdateAuthDataFor1PU: %w", err)
	}

	aadIndex := bytes.Index(auth, []byte("."))
	lastIndex := aadIndex

	if lastIndex < 0 {
		lastIndex = len(auth)
	}

	return je.buildCommonAuthData(aadIndex, kwAlg, string(auth[:lastIndex]), auth, apu, apv, epk)
}

func (je *JWEEncrypt) newEPK(cek []byte) (*spicrypto.PrivateKey, string, error) {
	var (
		kwAlg string
		epk   *spicrypto.PrivateKey
		err   error
	)

	switch je.recipientsKeys[0].Type {
	case "EC":
		epk, kwAlg, err = je.ecEPKAndAlg(cek)
		if err != nil {
			return nil, "", fmt.Errorf("newEPK: %w", err)
		}
	case "OKP":
		epk, kwAlg, err = je.okpEPKAndAlg()
		if err != nil {
			return nil, "", fmt.Errorf("newEPK: %w", err)
		}
	default:
		return nil, "", fmt.Errorf("newEPK: invalid key type: '%v'", je.recipientsKeys[0].Type)
	}

	return epk, kwAlg, nil
}

func (je *JWEEncrypt) ecEPKAndAlg(cek []byte) (*spicrypto.PrivateKey, string, error) {
	var kwAlg string

	curve, err := hybrid.GetCurve(je.recipientsKeys[0].Curve)
	if err != nil {
		return nil, "", fmt.Errorf("ecEPKAndAlg: getCurve: %w", err)
	}

	pk, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("ecEPKAndAlg: generate ec key: %w", err)
	}

	epk := &spicrypto.PrivateKey{
		PublicKey: spicrypto.PublicKey{
			Type:  "EC",
			Curve: pk.Curve.Params().Name,
			X:     pk.X.Bytes(),
			Y:     pk.Y.Bytes(),
		},
		D: pk.D.Bytes(),
	}

	two := 2

	switch len(cek) {
	case subtle.AES128Size * two:
		kwAlg = tinkcrypto.ECDH1PUA128KWAlg
	case subtle.AES192Size * two:
		kwAlg = tinkcrypto.ECDH1PUA192KWAlg
	case subtle.AES256Size * two:
		kwAlg = tinkcrypto.ECDH1PUA256KWAlg
	}

	return epk, kwAlg, nil
}

func (je *JWEEncrypt) okpEPKAndAlg() (*spicrypto.PrivateKey, string, error) {
	ephemeralPrivKey := make([]byte, cryptoutil.Curve25519KeySize)

	_, err := rand.Read(ephemeralPrivKey)
	if err != nil {
		return nil, "", fmt.Errorf("okpEPKAndAlg: generate random key for OKP: %w", err)
	}

	ephemeralPubKey, err := curve25519.X25519(ephemeralPrivKey, curve25519.Basepoint)
	if err != nil {
		return nil, "", fmt.Errorf("okpEPKAndAlg: generate public key for OKP: %w", err)
	}

	kwAlg := tinkcrypto.ECDH1PUA128KWAlg

	epk := &spicrypto.PrivateKey{
		PublicKey: spicrypto.PublicKey{
			Type:  "OKP",
			Curve: "X25519",
			X:     ephemeralPubKey,
		},
		D: ephemeralPrivKey,
	}

	return epk, kwAlg, nil
}

func (je *JWEEncrypt) buildCommonAuthData(aadIndex int, kwAlg, authData string,
	auth, apu, apv []byte, epk *spicrypto.PrivateKey) (*spicrypto.PrivateKey, []byte, map[string]interface{}, error) {
	authDataBytes, err := base64.RawURLEncoding.DecodeString(authData)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("buildCommonAuthData authData decode: %w", err)
	}

	authDataJSON := map[string]interface{}{}

	err = json.Unmarshal(authDataBytes, &authDataJSON)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("buildCommonAuthData authData unmarshal: %w", err)
	}

	if len(je.recipientsKeys) == 1 {
		authDataJSON["kid"] = je.recipientsKeys[0].KID
	}

	authDataJSON["alg"] = kwAlg

	marshalledEPK, err := convertRecEPKToMarshalledJWK(&epk.PublicKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("buildCommonAuthData epk marshall: %w", err)
	}
	authDataJSON["epk"] = json.RawMessage(marshalledEPK)

	encodedAPU := []byte(base64.RawURLEncoding.EncodeToString(apu))
	authDataJSON["apu"] = string(encodedAPU)

	encodeAPV := []byte(base64.RawURLEncoding.EncodeToString(apv))
	authDataJSON["apv"] = string(encodeAPV)

	newAuth, err := json.Marshal(authDataJSON)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("buildCommonAuthData authData marshall: %w", err)
	}

	authData = base64.RawURLEncoding.EncodeToString(newAuth)

	if aadIndex > 0 {
		authData += string(auth[aadIndex:])
	}

	return epk, []byte(authData), authDataJSON, nil
}

func NewJWEEncrypt(encAlg EncAlg, envelopMediaType, cty, senderKID string, senderKH *keyset.Handle,
	recipientsPubKeys []*spicrypto.PublicKey, crypto spicrypto.Crypto) (*JWEEncrypt, error) {
	if len(recipientsPubKeys) == 0 {
		return nil, errors.New("empty recipientsPubKeys list")
	}

	switch encAlg {
	case A256GCM, XC20P, A128CBCHS256, A192CBCHS384, A256CBCHS384, A256CBCHS512:
	default:
		return nil, fmt.Errorf("encryption algorithm '%s' not supported", encAlg)
	}

	if crypto == nil {
		return nil, errors.New("crypto service is required to create a JWEEncrypt instance")
	}

	if senderKH != nil {
		if senderKID == "" {
			return nil, errors.New("senderKID is required with senderKH")
		}
	}

	return &JWEEncrypt{
		recipientsKeys: recipientsPubKeys,
		skid:           senderKID,
		senderKH:       senderKH,
		encAlg:         encAlg,
		encTyp:         envelopMediaType,
		cty:            cty,
		crypto:         crypto,
	}, nil
}

func (je *JWEEncrypt) addExtraProtectedHeaders(protectedHeaders map[string]interface{}) {
	if je.cty != "" {
		protectedHeaders[HeaderContentType] = je.cty
	}

	if je.skid != "" {
		protectedHeaders[HeaderSenderKeyID] = je.skid
	}
}

func (je *JWEEncrypt) newCEK() []byte {
	twoKeys := 2
	defKeySize := 32

	switch je.encAlg {
	case A256GCM, XC20P:
		return random.GetRandomBytes(uint32(defKeySize))
	case A128CBCHS256:
		return random.GetRandomBytes(uint32(subtle.AES128Size * twoKeys))
	case A192CBCHS384:
		return random.GetRandomBytes(uint32(subtle.AES192Size * twoKeys))
	case A256CBCHS384:
		return random.GetRandomBytes(uint32(subtle.AES256Size + subtle.AES192Size))
	case A256CBCHS512:
		return random.GetRandomBytes(uint32(subtle.AES256Size * twoKeys))
	default:
		return random.GetRandomBytes(uint32(defKeySize))
	}
}

func (je *JWEEncrypt) useNISTPKW() bool {
	if je.senderKH == nil {
		return true
	}

	for _, ki := range je.senderKH.KeysetInfo().KeyInfo {
		switch ki.TypeUrl {
		case "type.hyperledger.org/hyperledger.aries.crypto.tink.NistPEcdhKwPublicKey",
			"type.hyperledger.org/hyperledger.aries.crypto.tink.NistPEcdhKwPrivateKey":
			return true
		case "type.hyperledger.org/hyperledger.aries.crypto.tink.X25519EcdhKwPublicKey",
			"type.hedgerledger.org/hyperledger.aries.crypto.tink.X25519EcdhKwPrivateKey":
			return false
		}
	}
	return true
}

func (je *JWEEncrypt) getECDHEncPrimitive(cek []byte) (api.CompositeEncrypt, error) {
	nistpKW := je.useNISTPKW()

	encAlg, ok := aeadAlg[je.encAlg]
	if !ok {
		return nil, fmt.Errorf("getECDHEncPrimitive: encAlg not supported: '%v'", je.encAlg)
	}

	kt := ecdh.KeyTemplateForECDHPrimitiveWithCEK(cek, nistpKW, encAlg)

	kh, err := keyset.NewHandle(kt)
	if err != nil {
		return nil, err
	}

	pubKH, err := kh.Public()
	if err != nil {
		return nil, err
	}

	return ecdh.NewECDHEncrypt(pubKH)
}

func computeAuthData(protectedHeaders map[string]interface{}, origProtectedHeader string,
	aad []byte) ([]byte, error) {
	var protected string

	if len(origProtectedHeader) > 0 {
		protected = origProtectedHeader
	} else if protectedHeaders != nil {
		protectedHeadersJSON := map[string]json.RawMessage{}

		for k, v := range protectedHeaders {
			mV, err := json.Marshal(v)
			if err != nil {
				return nil, fmt.Errorf("computeAuthData: %w", err)
			}

			rawMsg := json.RawMessage(mV)
			protectedHeadersJSON[k] = rawMsg
		}

		err := jwkMarshalEPK(protectedHeadersJSON)
		if err != nil {
			return nil, fmt.Errorf("computeAuthData: %w", err)
		}

		mProtected, err := json.Marshal(protectedHeadersJSON)
		if err != nil {
			return nil, fmt.Errorf("computeAuthData: %w", err)
		}

		protected = base64.RawURLEncoding.EncodeToString(mProtected)
	}

	output := []byte(protected)
	if len(aad) > 0 {
		output = append(output, '.')

		encLen := base64.RawURLEncoding.EncodedLen(len(aad))
		aadEncoded := make([]byte, encLen)

		base64.RawURLEncoding.Encode(aadEncoded, aad)
		output = append(output, aadEncoded...)
	}

	return output, nil
}

func jwkMarshalEPK(protectedHeadersJSON map[string]json.RawMessage) error {
	if protectedHeadersJSON[HeaderEPK] != nil {
		epk := &jwk.JWK{}

		err := epk.UnmarshalJSON(protectedHeadersJSON[HeaderEPK])
		if err != nil {
			return err
		}

		mEPK, err := epk.MarshalJSON()
		if err != nil {
			return fmt.Errorf("jwkMarshalEPK: %w", err)
		}

		protectedHeadersJSON[HeaderEPK] = mEPK
	}

	return nil
}

func convertRecEPKToMarshalledJWK(recEPK *spicrypto.PublicKey) ([]byte, error) {
	var (
		c   elliptic.Curve
		err error
		key interface{}
	)

	switch recEPK.Type {
	case ecdhpb.KeyType_EC.String():
		c, err = hybrid.GetCurve(recEPK.Curve)
		if err != nil {
			return nil, err
		}

		key = &ecdsa.PublicKey{
			Curve: c,
			X:     new(big.Int).SetBytes(recEPK.X),
			Y:     new(big.Int).SetBytes(recEPK.Y),
		}
	case ecdhpb.KeyType_OKP.String():
		key = recEPK.X
	default:
		return nil, errors.New("invalid key type")
	}

	recJWK := jwk.JWK{
		JSONWebKey: jose.JSONWebKey{
			Key: key,
		},
		Kty: recEPK.Type,
		Crv: recEPK.Curve,
	}

	return recJWK.MarshalJSON()
}
