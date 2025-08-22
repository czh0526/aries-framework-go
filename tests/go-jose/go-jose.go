package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	josecipher "github.com/go-jose/go-jose/v3/cipher"
	"log"
)

func main() {
	testECDHES()
}

func testECDHES() {
	// 生成发送方的 ECDSA 公私钥
	senderPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("生成发送方私钥失败: %v", err)
	}
	senderPubKey := &senderPrivKey.PublicKey

	// 生成接收方的 ECDSA 公私钥
	recipientPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("生成接收方私钥失败: %v", err)
	}
	recipientPubKey := &recipientPrivKey.PublicKey

	// 随机生成 apu, apv
	apu := []byte("PartyU-Identifier")
	apv := []byte("PartyV-Identifier")

	keySize := 256

	// 发送方生成共享密钥
	sharedKey := josecipher.DeriveECDHES("ECDH-ES", apu, apv, senderPrivKey, recipientPubKey, keySize)
	fmt.Printf("sharedKey: %x\n", sharedKey)

	// 接收方生成共享密钥
	deriveKey := josecipher.DeriveECDHES("ECDH-ES", apu, apv, recipientPrivKey, senderPubKey, keySize)
	fmt.Printf("deriveKey: %x\n", deriveKey)

	// 看看双方派生的共享密钥是否相等
	if bytes.Compare(sharedKey, deriveKey) == 0 {
		fmt.Println("派生的密钥一致！ECDH 密钥交换成功！")
	} else {
		log.Fatalf("派生密钥不一致！发生错误。")
	}
}
