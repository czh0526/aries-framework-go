package kms

type KeyManager interface {
}

type Store interface {
}

type Provider interface {
}

type Creator func(provider Provider) (KeyManager, error)
