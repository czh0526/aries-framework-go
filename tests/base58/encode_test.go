package base58

import (
	"encoding/base64"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEncode(t *testing.T) {
	pubKey, err := base64.RawURLEncoding.DecodeString("ef2CXTSo3XTbf86JhU-ywP3o-90Kes4afp1VDKnO1aE")
	assert.NoError(t, err)

	encoded := base58.Encode(pubKey)
	fmt.Println(encoded)
}
