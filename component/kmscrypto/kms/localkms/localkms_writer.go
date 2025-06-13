package localkms

import (
	"encoding/base64"
	"errors"
	"fmt"
	comp_kms "github.com/czh0526/aries-framework-go/component/kmscrypto/kms"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
)

const maxKeyIDLen = 50

func newWriter(kmsStore spikms.Store, opts ...spikms.PrivateKeyOpts) *storeWriter {
	pOpts := spikms.NewOpt()

	for _, opt := range opts {
		opt(pOpts)
	}

	return &storeWriter{
		storage:           kmsStore,
		requestedKeysetID: pOpts.KsID(),
	}
}

type storeWriter struct {
	storage           spikms.Store
	requestedKeysetID string
	KeysetID          string
}

func (l *storeWriter) Write(p []byte) (int, error) {
	var err error
	var ksID string

	if l.requestedKeysetID != "" {
		ksID, err = l.verifyRequestedID()
		if err != nil {
			return 0, err
		}

	} else {
		ksID, err = l.newKeysetID()
		if err != nil {
			return 0, err
		}
	}

	err = l.storage.Put(ksID, p)
	if err != nil {
		return 0, err
	}

	l.KeysetID = ksID

	return len(p), nil
}

func (l *storeWriter) newKeysetID() (string, error) {
	keySetIDLength := base64.RawURLEncoding.DecodedLen(maxKeyIDLen)

	var ksID string
	for {
		// 随机构建一个 ksID
		ksID = base64.RawURLEncoding.EncodeToString(random.GetRandomBytes(uint32(keySetIDLength)))
		// 对 ksID 查重
		_, err := l.storage.Get(ksID)
		if err != nil {
			if errors.Is(err, comp_kms.ErrKeyNotFound) {
				break
			}
			return "", err
		}
	}

	return ksID, nil
}

func (l *storeWriter) verifyRequestedID() (string, error) {
	_, err := l.storage.Get(l.requestedKeysetID)
	if errors.Is(err, comp_kms.ErrKeyNotFound) {
		return l.requestedKeysetID, nil
	}

	if err != nil {
		return "", fmt.Errorf("got error while verifying requested ID: %w", err)
	}

	return "", fmt.Errorf("requested ID `%s` already exists, connot write keyset", l.requestedKeysetID)
}
