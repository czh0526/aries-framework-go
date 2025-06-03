package secretlock

type Service interface {
	Encrypt(keyURI string, req *EncryptRequest) (*EncryptResponse, error)

	Decrypt(keyURI string, req *DecryptRequest) (*DecryptResponse, error)
}

type EncryptRequest struct {
	Plaintext                   string
	AdditionalAuthenticatedData string
}

type DecryptRequest struct {
	Ciphertext                  string
	AdditionalAuthenticatedData string
}

type EncryptResponse struct {
	Ciphertext string
}

type DecryptResponse struct {
	Plaintext string
}
