package main

import (
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/chacha20poly1305"
	"log"
)

func main() {
	key := make([]byte, chacha20poly1305.KeySize)
	_, err := rand.Read(key)
	if err != nil {
		log.Fatalf("failed to generate random key: %v", err)
	}

	nonce := make([]byte, chacha20poly1305.NonceSize)
	_, err = rand.Read(nonce)
	if err != nil {
		log.Fatalf("failed to generate random nonce: %v", err)
	}

	plaintext := []byte("Hello, ChaCha20-Poly1305!")
	aad := []byte("Associated Data")

	// 构造
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		log.Fatalf("failed to create ChaCha20-Poly1305 instance: %v", err)
	}

	// 加密
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	fmt.Printf("Ciphertext: %x\n", ciphertext)

	// 解密
	decrypted, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		log.Fatalf("failed to decrypt ciphertext: %v", err)
	}

	fmt.Printf("Decrypted: %s\n", decrypted)
}
