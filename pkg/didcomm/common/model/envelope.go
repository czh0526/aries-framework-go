package model

type Envelope struct {
	Protected  string `json:"protected,omitempty"`
	IV         string `json:"iv,omitempty"`
	CipherText string `json:"ciphertext,omitempty"`
	Tag        string `json:"tag,omitempty"`
}
