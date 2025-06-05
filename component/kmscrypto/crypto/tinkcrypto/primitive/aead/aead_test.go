package aead

import (
	tinkaead "github.com/google/tink/go/aead"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"log"
)

func Example() {
	kh, err := keyset.NewHandle(aead.AES128CBCHMACSHA256KeyTemplate())
	if err != nil {
		log.Fatal(err)
	}

	a, err := tinkaead.New(kh)
	if err != nil {
		log.Fatal(err)
	}
}
