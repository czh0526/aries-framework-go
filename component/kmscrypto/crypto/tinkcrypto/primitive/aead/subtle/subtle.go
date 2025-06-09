package subtle

import "fmt"

const (
	maxInt     = int(^uint(0) >> 1)
	AES128Size = 16
	AES192Size = 24
	AES256Size = 32
)

func ValidateAESKeySize(sizeInBytes uint32) error {
	switch sizeInBytes {
	case AES128Size, AES192Size, AES256Size:
		return nil
	default:
		return fmt.Errorf("unvalid AES key size: want 16, 24 or 32, got %d", sizeInBytes)
	}
}
