package bbs12381g2pub

import (
	ml "github.com/IBM/mathlib"
)

type PublicKey struct {
	PointG2 *ml.G2
}

type PrivateKey struct {
	FR *ml.Zr
}
