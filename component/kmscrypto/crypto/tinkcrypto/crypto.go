package tinkcrypto

import "log"

type Crypto struct {
}

func New() (*Crypto, error) {
	log.Printf("【default】New tink crypto")
	return &Crypto{}, nil
}
