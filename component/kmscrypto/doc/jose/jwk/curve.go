package jwk

import "crypto/elliptic"

func CurveSize(crv elliptic.Curve) int {
	bits := crv.Params().BitSize
	byteSize := 8

	div := bits / byteSize
	mod := bits % byteSize

	if mod == 0 {
		return div
	}

	return div + 1
}
