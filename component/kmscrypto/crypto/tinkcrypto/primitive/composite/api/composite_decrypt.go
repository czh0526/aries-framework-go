package api

type CompositeDecrypt interface {
	Decrypt(ciphertext, additionalData []byte) ([]byte, error)
}
