package localkms

import (
	"bytes"
	"fmt"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
)

func newReader(store spikms.Store, keysetID string) *storeReader {
	return &storeReader{
		storage:  store,
		keysetID: keysetID,
	}
}

type storeReader struct {
	buf      *bytes.Buffer
	storage  spikms.Store
	keysetID string
}

func (l *storeReader) Read(p []byte) (int, error) {
	if l.buf == nil {
		if l.keysetID == "" {
			return 0, fmt.Errorf("keysetID is not set")
		}

		data, err := l.storage.Get(l.keysetID)
		if err != nil {
			return 0, fmt.Errorf("cannot read data from keysetID: %s: %w", l.keysetID, err)
		}

		l.buf = bytes.NewBuffer(data)
	}

	return l.buf.Read(p)
}
