package didkeyutil

import (
	"github.com/btcsuite/btcutil/base58"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/fingerprint"
	"strings"
)

func ConvertBase58KeysToDIDKeys(keys []string) []string {
	var didKeys []string

	for _, key := range keys {
		if key == "" {
			didKeys = append(didKeys, key)
			continue
		}

		if strings.Contains("?/#", string(key[0])) {
			didKeys = append(didKeys, key)
			continue
		}

		if strings.HasPrefix(key, "did:") {
			didKeys = append(didKeys, key)
			continue
		}

		rawKey := base58.Decode(key)
		if len(rawKey) == 0 {
			didKeys = append(didKeys, key)
			continue
		}

		didKey, _ := fingerprint.CreateDIDKey(rawKey)
		didKeys = append(didKeys, didKey)
	}

	return didKeys
}

func ConvertDIDKeysToBase58Keys(keys []string) []string {
	var base58Keys []string

	for _, key := range keys {
		if strings.HasPrefix(key, "did:key:") {
			rawKey, _ := fingerprint.PubKeyFromDIDKey(key)

			base58Keys = append(base58Keys, base58.Encode(rawKey))
		} else {
			base58Keys = append(base58Keys, key)
		}
	}

	return base58Keys
}
