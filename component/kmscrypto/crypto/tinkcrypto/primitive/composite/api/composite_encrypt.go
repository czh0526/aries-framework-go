package api

type CompositeEncrypt interface {
	Encrypt(plaintext, aad []byte) ([]byte, error)
}
