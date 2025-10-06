package did

import (
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	"github.com/multiformats/go-multibase"
	"strings"
)

type VerificationMethod struct {
	ID                string
	Type              string
	Controller        string
	Value             []byte
	jsonWebKey        *jwk.JWK
	relativeURL       bool
	multibaseEncoding multibase.Encoding
}

func (vm *VerificationMethod) JSONWebKey() *jwk.JWK {
	return vm.jsonWebKey
}

func NewVerificationMethodFromJWK(id, keyType, controller string, j *jwk.JWK) (*VerificationMethod, error) {
	pkBytes, err := j.PublicKeyBytes()
	if err != nil {
		return nil, fmt.Errorf("convert JWK to public key bytes failed, err = %w", err)
	}

	relativeURL := false
	if strings.HasPrefix(id, "#") {
		relativeURL = true
	}

	return &VerificationMethod{
		ID:          id,
		Type:        keyType,
		Controller:  controller,
		Value:       pkBytes,
		jsonWebKey:  j,
		relativeURL: relativeURL,
	}, nil
}

func populateRawVM(context, didID, baseURI string, pks []VerificationMethod) ([]map[string]interface{}, error) {
	var rawVM []map[string]interface{}

	for i := range pks {
		vm, err := populateRawVerificationMethod(context, didID, baseURI, &pks[i])
		if err != nil {
			return nil, err
		}

		rawVM = append(rawVM, vm)
	}

	return rawVM, nil
}

func populateRawVerificationMethod(context, didID, baseURI string,
	vm *VerificationMethod) (map[string]interface{}, error) {

	rawVM := make(map[string]interface{})
	rawVM[jsonldID] = vm.ID

	if vm.relativeURL {
		rawVM[jsonldID] = makeRelativeDIDURL(vm.ID, baseURI, didID)
	}

	rawVM[jsonldType] = vm.Type

	if context == contextV011 {
		rawVM[jsonldOwner] = vm.Controller
	} else {
		rawVM[jsonldController] = vm.Controller
	}

	if vm.jsonWebKey != nil {
		jwkBytes, err := json.Marshal(vm.jsonWebKey)
		if err != nil {
			return nil, err
		}

		rawVM[jsonldPublicKeyjwk] = json.RawMessage(jwkBytes)

	} else if vm.Type == "Ed25519VerificationKey2020" {
		var err error

		rawVM[jsonldPublicKeyMultibase], err = multibase.Encode(vm.multibaseEncoding, vm.Value)
		if err != nil {
			return nil, err
		}

	} else if vm.Value != nil {
		rawVM[jsonldPublicKeyBase58] = base58.Encode(vm.Value)
	}

	return rawVM, nil
}

func populateVerificationMethod(context, didID, baseURI string,
	rawVM []map[string]interface{}) ([]VerificationMethod, error) {
	var verificationMethods []VerificationMethod

	for _, v := range rawVM {
		controllerKey := jsonldController
		if context == contextV011 {
			controllerKey = jsonldOwner
		}

		id := stringEntry(v[jsonldID])
		controller := stringEntry(v[controllerKey])

		isRelative := false

		if strings.HasPrefix(id, "#") {
			id = resolveRelativeDIDURL(didID, baseURI, id)
			split := strings.Split(id, "#")
			controller = split[0]
			isRelative = true
		}

		vm := VerificationMethod{
			ID:          id,
			Type:        stringEntry(v[jsonldType]),
			Controller:  controller,
			relativeURL: isRelative,
		}

		err := decodeVM(&vm, v)
		if err != nil {
			return nil, err
		}

		verificationMethods = append(verificationMethods, vm)
	}

	return verificationMethods, nil
}

func decodeVM(vm *VerificationMethod, rawPK map[string]interface{}) error {
	if stringEntry(rawPK[jsonldPublicKeyBase58]) != "" {
		vm.Value = base58.Decode(stringEntry(rawPK[jsonldPublicKeyBase58]))
		return nil
	}

	if stringEntry(rawPK[jsonldPublicKeyMultibase]) != "" {
		multibaseEncoding, value, err := multibase.Decode(stringEntry(rawPK[jsonldPublicKeyMultibase]))
		if err != nil {
			return err
		}

		vm.Value = value
		vm.multibaseEncoding = multibaseEncoding

		return nil
	}

	if stringEntry(rawPK[jsonldPublicKeyHex]) != "" {
		value, err := hex.DecodeString(stringEntry(rawPK[jsonldPublicKeyHex]))
		if err != nil {
			return fmt.Errorf("decode public key hex failed, err = %w", err)
		}

		vm.Value = value
		return nil
	}

	if stringEntry(rawPK[jsonldPublicKeyPem]) != "" {
		block, _ := pem.Decode([]byte(stringEntry(rawPK[jsonldPublicKeyPem])))
		if block == nil {
			return errors.New("decode public key pem failed")
		}

		vm.Value = block.Bytes
		return nil
	}

	if jwkMap := mapEntry(rawPK[jsonldPublicKeyjwk]); jwkMap != nil {
		return decodeVMJwk(jwkMap, vm)
	}

	return errors.New("public key encoding not supported")
}

func decodeVMJwk(jwkMap map[string]interface{}, vm *VerificationMethod) error {
	jwkBytes, err := json.Marshal(jwkMap)
	if err != nil {
		return fmt.Errorf("failed to marshal '%s', cause: %w ", jsonldPublicKeyjwk, err)
	}

	if string(jwkBytes) == "{}" {
		vm.Value = []byte("")
		return nil
	}

	var j jwk.JWK

	err = json.Unmarshal(jwkBytes, &j)
	if err != nil {
		return fmt.Errorf("unmarshal JWK: %w", err)
	}

	pkBytes, err := j.PublicKeyBytes()
	if err != nil {
		return fmt.Errorf("failed to decode public key from JWK: %w", err)
	}

	vm.Value = pkBytes
	vm.jsonWebKey = &j

	return nil
}
