package main

import (
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/nacl/box"
	"log"
)

func main() {
	senderPublicKey, senderPrivateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	recipientPublicKey, recipientPrivateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	message := []byte("Hello, secure World")

	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		log.Fatal(err)
	}

	ciphertext := box.Seal(nil, message, &nonce, recipientPublicKey, senderPrivateKey)
	fmt.Printf("ciphertext: %x\n", ciphertext)

	plaintext, ok := box.Open(nil, ciphertext, &nonce, senderPublicKey, recipientPrivateKey)
	if !ok {
		log.Fatal("failed to decrypt message")
	}

	fmt.Printf("plaintext: `%s`\n", plaintext)
}
