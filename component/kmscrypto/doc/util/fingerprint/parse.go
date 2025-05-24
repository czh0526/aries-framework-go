package fingerprint

import (
	"fmt"
	"strings"
)

func MethodIDFromDIDKey(didKey string) (string, error) {
	msID, err := getMethodSpecificID(didKey)
	if err != nil {
		return "", err
	}

	if !strings.HasPrefix(msID, "z") {
		return "", fmt.Errorf("not a valid did:key identifier (not a base58btc multicodec): %s", didKey)
	}

	return msID, nil
}

func getMethodSpecificID(did string) (string, error) {
	parts := strings.SplitN(did, ":", 3)

	if len(parts) < 3 {
		return "", fmt.Errorf("invalid DID: %s", did)
	}

	return parts[2], nil
}
