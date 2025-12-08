package internal

import "fmt"

const (
	CredentialNameKey   = "vcname_"
	PresentationNameKey = "vpname_"

	credentialNameDataKeyPattern   = CredentialNameKey + "%s"
	presentationNameDataKeyPattern = PresentationNameKey + "%s"
)

func CredentialNameDataKey(name string) string {
	return fmt.Sprintf(credentialNameDataKeyPattern, name)
}

func PresentationNameDataKey(name string) string {
	return fmt.Sprintf(presentationNameDataKeyPattern, name)
}
