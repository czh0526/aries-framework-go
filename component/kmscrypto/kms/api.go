package kms

import "errors"

var ErrKeyNotFound = errors.New("key not found")

type CryptoBox interface {
}
