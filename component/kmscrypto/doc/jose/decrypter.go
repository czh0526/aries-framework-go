package jose

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/api"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/ecdh"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/keyio"
	ecdhpb "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	resolver "github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose/kidresolver"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"strings"
)

type Decrypter interface {
	Decrypt(jwe *JSONWebEncryption) ([]byte, error)
}

type JWEDecrypt struct {
	kidResolvers []resolver.KIDResolver
	crypto       spicrypto.Crypto
	kms          spikms.KeyManager
}

func (jd *JWEDecrypt) Decrypt(jwe *JSONWebEncryption) ([]byte, error) {
	encAlg, err := jd.validateAndExtractProtectedHeaders(jwe)
	if err != nil {
		return nil, fmt.Errorf("jwedecrypt: %w", err)
	}

	var wkOpts []spicrypto.WrapKeyOpts

	skid, ok := jwe.ProtectedHeaders.SenderKeyID()
	if !ok {
		skid, ok = fetchSKIDFromAPU(jwe)
	}

	if ok && skid != "" {
		senderKH, e := jd.fetchSenderPubKey(skid, EncAlg(encAlg))
		if e != nil {
			return nil, fmt.Errorf("jwedecrypt: failed to fetch sender public key for skid: %w", e)
		}

		wkOpts = append(wkOpts, spicrypto.WithSender(senderKH), spicrypto.WithTag([]byte(jwe.Tag)))
	}

	recWK, err := buildRecipientsWrappedKey(jwe)
	if err != nil {
		return nil, fmt.Errorf("jwedecrypt: failed to build recipients WK: %w", err)
	}

	cek, err := jd.unwrapCEK(recWK, wkOpts...)
	if err != nil {
		return nil, fmt.Errorf("jwedecrypt: failed to unwrap CEK: %w", err)
	}

	if len(recWK) == 1 {
		marshaleldEPK, err := convertRecEPKToMarshalledJWK(&recWK[0].EPK)
		if err != nil {
			return nil, fmt.Errorf("jwedecrypt: %w", err)
		}

		jwe.ProtectedHeaders["epk"] = json.RawMessage(marshaleldEPK)
	}

	return jd.decryptJWE(jwe, cek)
}

func (jd *JWEDecrypt) unwrapCEK(recWK []*spicrypto.RecipientWrappedKey,
	senderOpt ...spicrypto.WrapKeyOpts) ([]byte, error) {
	var (
		cek  []byte
		errs []error
	)

	for _, rec := range recWK {
		var unwrapOpts []spicrypto.WrapKeyOpts

		if strings.HasPrefix(rec.KID, "did:key") || strings.Index(rec.KID, "#") > 0 {
			resolvedRec, err := jd.resolveKID(rec.KID)
			if err != nil {
				errs = append(errs, err)
				continue
			}

			rec.KID = resolvedRec.KID
		}

		recKH, err := jd.kms.Get(rec.KID)
		if err != nil {
			continue
		}

		if rec.EPK.Type == ecdhpb.KeyType_OKP.String() {
			unwrapOpts = append(unwrapOpts, spicrypto.WithXC20PKW())
		}

		if senderOpt != nil {
			unwrapOpts = append(unwrapOpts, senderOpt...)
		}

		if len(unwrapOpts) > 0 {
			cek, err = jd.crypto.UnwrapKey(rec, recKH, unwrapOpts...)
		} else {
			cek, err = jd.crypto.UnwrapKey(rec, recKH)
		}

		if err == nil {
			break
		}

		errs = append(errs, err)
	}

	if len(cek) == 0 {
		return nil, fmt.Errorf("failed to unwrap cek: %v", errs)
	}

	return cek, nil
}

func (jd *JWEDecrypt) fetchSenderPubKey(skid string, encAlg EncAlg) (*keyset.Handle, error) {
	senderKey, err := jd.resolveKID(skid)
	if err != nil {
		return nil, fmt.Errorf("fetchSenderPubKey: %w", err)
	}

	ceAlg := aeadAlg[encAlg]
	if ceAlg <= 0 {
		return nil, fmt.Errorf("fetchSenderPubKey: invalid content encALg: '%s'", encAlg)
	}

	return keyio.PublicKeyToKeysetHandle(senderKey, ceAlg)
}

func (jd *JWEDecrypt) resolveKID(kid string) (*spicrypto.PublicKey, error) {
	var errs []error

	for _, resolver := range jd.kidResolvers {
		rKID, err := resolver.Resolve(kid)
		if err != nil {
			return rKID, nil
		}

		errs = append(errs, err)
	}

	return nil, fmt.Errorf("resolveKID: %v", errs)
}

func (jd *JWEDecrypt) validateAndExtractProtectedHeaders(jwe *JSONWebEncryption) (string, error) {
	if jwe == nil {
		return "", fmt.Errorf("jwe is nil")
	}

	if len(jwe.ProtectedHeaders) == 0 {
		return "", fmt.Errorf("jwe has no protected headers")
	}

	protectedHeaders := jwe.ProtectedHeaders

	encAlg, ok := protectedHeaders.Encryption()
	if !ok {
		return "", fmt.Errorf("jwe is missing encryption algorithm 'enc' header")
	}

	switch encAlg {
	case string(A256GCM), string(XC20P), string(A128CBCHS256),
		string(A192CBCHS384), string(A256CBCHS384), string(A256CBCHS512):
	default:
		return "", fmt.Errorf("encryption algorithm '%s' not supported", encAlg)
	}

	return encAlg, nil
}

func (jd *JWEDecrypt) decryptJWE(jwe *JSONWebEncryption, cek []byte) ([]byte, error) {
	encAlg, ok := jwe.ProtectedHeaders.Encryption()
	if !ok {
		return nil, fmt.Errorf("jwedecrypt: JWE 'enc'' protected header is missing")
	}

	decPrimitive, err := getECDHDecPrimitive(cek, EncAlg(encAlg), true)
	if err != nil {
		return nil, fmt.Errorf("jwedecrypt: failed to get decryption primitive: %w", err)
	}

	encryptedData, err := buildEncryptedData(jwe)
	if err != nil {
		return nil, fmt.Errorf("jwedecrypt: failed to build encryptedData for Decrypt(): %w", err)
	}

	aadBytes := []byte(jwe.AAD)

	authData, err := computeAuthData(jwe.ProtectedHeaders, jwe.OrigProtectedHdrs, aadBytes)
	if err != nil {
		return nil, err
	}

	return decPrimitive.Decrypt(encryptedData, authData)
}

func buildEncryptedData(jwe *JSONWebEncryption) ([]byte, error) {
	encData := new(composite.EncryptedData)
	encData.Tag = []byte(jwe.Tag)
	encData.IV = []byte(jwe.IV)
	encData.Ciphertext = []byte(jwe.Ciphertext)

	return json.Marshal(encData)
}

func buildRecipientsWrappedKey(jwe *JSONWebEncryption) ([]*spicrypto.RecipientWrappedKey, error) {
	var (
		recipients []*spicrypto.RecipientWrappedKey
		err        error
	)

	for _, recJWE := range jwe.Recipients {
		headers := recJWE.Header
		alg, ok := jwe.ProtectedHeaders.Algorithm()
		is1PU := ok && strings.Contains(strings.ToUpper(alg), "1PU")

		if len(jwe.Recipients) == 1 || is1PU {
			headers, err = extractRecipientHeaders(jwe.ProtectedHeaders)
			if err != nil {
				return nil, err
			}
		}

		var recWK *spicrypto.RecipientWrappedKey
		if is1PU && len(jwe.Recipients) > 1 {
			headers.KID = recJWE.Header.KID
		}

		recWK, err = createRecWK(headers, []byte(recJWE.EncryptedKey))
		if err != nil {
			return nil, err
		}

		recipients = append(recipients, recWK)
	}

	return recipients, nil
}

func createRecWK(headers *RecipientHeaders, encryptedKey []byte) (*spicrypto.RecipientWrappedKey, error) {
	recWK, err := convertMarshalledJWKToRecKey(headers.EPK)
	if err != nil {
		return nil, err
	}

	recWK.KID = headers.KID
	recWK.Alg = headers.Alg

	err = updateAPUAPVInRecWK(recWK, headers)
	if err != nil {
		return nil, err
	}

	recWK.EncryptedCEK = encryptedKey

	return recWK, nil
}

func updateAPUAPVInRecWK(recWK *spicrypto.RecipientWrappedKey, headers *RecipientHeaders) error {
	decodedAPU, decodedAPV, err := decodeAPUAPV(headers)
	if err != nil {
		return fmt.Errorf("updateAPUAPVInRecWK: %w", err)
	}

	recWK.APU = decodedAPU
	recWK.APV = decodedAPV

	return nil
}

func convertMarshalledJWKToRecKey(marshalledJWK []byte) (*spicrypto.RecipientWrappedKey, error) {
	j := &jwk.JWK{}

	err := j.UnmarshalJSON(marshalledJWK)
	if err != nil {
		return nil, err
	}

	epk := spicrypto.PublicKey{
		Curve: j.Crv,
		Type:  j.Kty,
	}

	switch key := j.Key.(type) {
	case *ecdsa.PublicKey:
		epk.X = key.X.Bytes()
		epk.Y = key.Y.Bytes()
	case []byte:
		epk.X = key
	default:
		return nil, fmt.Errorf("unsupported recipient key type")
	}

	return &spicrypto.RecipientWrappedKey{
		KID: j.KeyID,
		EPK: epk,
	}, nil
}

func extractRecipientHeaders(headers map[string]interface{}) (*RecipientHeaders, error) {
	mapData, ok := headers[HeaderEPK].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("JSON value is not a map(%#v)", headers[HeaderEPK])
	}

	epkBytes, err := json.Marshal(mapData)
	if err != nil {
		return nil, err
	}

	epk := json.RawMessage{}

	err = json.Unmarshal(epkBytes, &epk)
	if err != nil {
		return nil, err
	}

	alg := ""
	if headers[HeaderAlgorithm] != nil {
		alg = fmt.Sprintf("%v", headers[HeaderAlgorithm])
	}

	kid := ""
	if headers[HeaderKeyID] != nil {
		kid = fmt.Sprintf("%v", headers[HeaderKeyID])
	}

	apu := ""
	if headers["apu"] != nil {
		apu = fmt.Sprintf("%v", headers["apu"])
	}

	apv := ""
	if headers["apv"] != nil {
		apv = fmt.Sprintf("%v", headers["apv"])
	}

	recHeaders := &RecipientHeaders{
		Alg: alg,
		KID: kid,
		EPK: epk,
		APU: apu,
		APV: apv,
	}

	return recHeaders, nil
}

func NewJWEDecrypt(kidResolvers []resolver.KIDResolver, c spicrypto.Crypto, k spikms.KeyManager) *JWEDecrypt {
	return &JWEDecrypt{
		kidResolvers: kidResolvers,
		crypto:       c,
		kms:          k,
	}
}

func getECDHDecPrimitive(cek []byte, encAlg EncAlg, nistpKW bool) (api.CompositeDecrypt, error) {
	ceAlg := aeadAlg[encAlg]

	if ceAlg <= 0 {
		return nil, fmt.Errorf("invalid content encAlg: '%s'", encAlg)
	}

	kt := ecdh.KeyTemplateForECDHPrimitiveWithCEK(cek, nistpKW, ceAlg)

	kh, err := keyset.NewHandle(kt)
	if err != nil {
		return nil, err
	}

	return ecdh.NewECDHCrypto(kh)
}

func fetchSKIDFromAPU(jwe *JSONWebEncryption) (string, bool) {
	if len(jwe.Recipients) > 1 {
		if a, apuOK := jwe.ProtectedHeaders["apu"]; apuOK {
			skidBytes, err := base64.RawURLEncoding.DecodeString(a.(string))
			if err != nil {
				return "", false
			}

			return string(skidBytes), true
		}
	}

	return "", false
}
