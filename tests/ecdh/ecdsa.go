package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func main() {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	xBytes := key.PublicKey.X.Bytes()
	yBytes := key.PublicKey.Y.Bytes()
	dBytes := key.D.Bytes()

	fmt.Printf("d => %s\n", base64.RawURLEncoding.EncodeToString(dBytes))
	fmt.Printf("x => %s\n", base64.RawURLEncoding.EncodeToString(xBytes))
	fmt.Printf("y => %s\n", base64.RawURLEncoding.EncodeToString(yBytes))
}
