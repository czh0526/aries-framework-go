package key

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose/jwk/jwksupport"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/fingerprint"
	didmodel "github.com/czh0526/aries-framework-go/component/models/did"
	spivdr "github.com/czh0526/aries-framework-go/spi/vdr"
	"regexp"
)

func (v *VDR) Read(didKey string, _ ...spivdr.DIDMethodOption) (*didmodel.DocResolution, error) {
	parsed, err := didmodel.Parse(didKey)
	if err != nil {
		return nil, fmt.Errorf("pub:key vdr Read: failed to parse DID document: %w", err)
	}

	if parsed.Method != "key" {
		return nil, fmt.Errorf("vdr Read: invalid did:key method: %s", parsed.Method)
	}

	if !isValidMethodID(parsed.MethodSpecificID) {
		return nil, fmt.Errorf("vdr Read: invalid did:key method ID: %s", parsed.Method)
	}

	pubKeyBytes, code, err := fingerprint.PubKeyFromFingerprint(parsed.MethodSpecificID)
	if err != nil {
		return nil, fmt.Errorf("vdr Read: failed to get public key from fingerPrint: %w", err)
	}

	didDoc, err := createDIDDocFromPubKey(parsed.MethodSpecificID, code, pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("create DID document from public key failed: %w", err)
	}

	return &didmodel.DocResolution{
		Context:     []string{schemaResV1},
		DIDDocument: didDoc,
	}, nil
}

func isValidMethodID(id string) bool {
	r := regexp.MustCompile(`(z)([1-9a-km-zA-HJ-NP-Z]{46})`)
	return r.MatchString(id)
}

func createDIDDocFromPubKey(kid string, code uint64, pubKeyBytes []byte) (*didmodel.Doc, error) {
	switch code {
	case fingerprint.ED25519PubKeyMultiCodec:
		return createEd25519DIDDoc(kid, pubKeyBytes)
	case fingerprint.BLS12381g2PubKeyMultiCodec, fingerprint.BLS12381g1g2PubKeyMultiCodec:
		return createBase58DIDDoc(kid, bls12381G2Key2020, pubKeyBytes)
	case fingerprint.P256PubKeyMultiCodec, fingerprint.P384PubKeyMultiCodec, fingerprint.P521PubKeyMultiCodec:
		return createJSONWebKey2020IDDDoc(kid, code, pubKeyBytes)
	}

	return nil, fmt.Errorf("unsupported key multicodec code [0x%x]", code)
}

func createEd25519DIDDoc(kid string, pubKeyBytes []byte) (*didmodel.Doc, error) {
	didKey := fmt.Sprintf("did:key:%s", kid)

	// 转化 ECDH 公钥
	keyAgr, err := keyAgreementFromEd25519(didKey, pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("pub:key vdr Read: faled to fetch KeyAgreement: %w", err)
	}

	keyID := fmt.Sprintf("%s#%s", didKey, kid)
	publicKey := didmodel.NewVerificationMethodFromBytes(keyID, ed25519VerificationKey2018, didKey, pubKeyBytes)

	didDoc := createDoc(publicKey, keyAgr, didKey)

	return didDoc, nil
}

func createBase58DIDDoc(kid string, keyType string, pubKeyBytes []byte) (*didmodel.Doc, error) {
	didKey := fmt.Sprintf("did:key:%s", kid)

	keyID := fmt.Sprintf("%s#%s", didKey, kid)
	publicKey := didmodel.NewVerificationMethodFromBytes(keyID, keyType, didKey, pubKeyBytes)

	didDoc := createDoc(publicKey, publicKey, didKey)

	return didDoc, nil
}

func createJSONWebKey2020IDDDoc(kid string, code uint64, pubKeyBytes []byte) (*didmodel.Doc, error) {
	didKey := fmt.Sprintf("did:key:%s", kid)

	keyID := fmt.Sprintf("%s#%s", didKey, kid)

	var curve elliptic.Curve
	switch code {
	case fingerprint.P256PubKeyMultiCodec:
		curve = elliptic.P256()
	case fingerprint.P384PubKeyMultiCodec:
		curve = elliptic.P384()
	case fingerprint.P521PubKeyMultiCodec:
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported key multicodec code for JsonWebKey [0x%x]", code)
	}

	x, y := elliptic.UnmarshalCompressed(curve, pubKeyBytes)
	if x == nil {
		return nil, fmt.Errorf("error unmarshal public key")
	}

	publicKey := ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
	j, err := jwksupport.JWKFromKey(&publicKey)
	if err != nil {
		return nil, fmt.Errorf("error creating JWK %w", err)
	}

	vm, err := didmodel.NewVerificationMethodFromJWK(keyID, jsonWebKey2020, didKey, j)
	if err != nil {
		return nil, fmt.Errorf("error creating verification method %w", err)
	}

	didDoc := createDoc(vm, vm, didKey)

	return didDoc, nil
}
