package localkms

import (
	"github.com/stretchr/testify/require"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"testing"
)

func TestLocalKMSWriter(t *testing.T) {
	t.Run("success case - create a valid storeWriter and store 20 non empty random keys", func(t *testing.T) {
		keys := map[string][]byte{}
		mockStore := &inMemoryKMSStore{keys: keys}

		for i := 0; i < 256; i++ {
			l := newWriter(mockStore)
			require.NotEmpty(t, l)

			someKey := random.GetRandomBytes(uint32(32))
			n, err := l.Write(someKey)
			require.NoError(t, err)
			require.Equal(t, len(someKey), n)
			require.Equal(t, maxKeyIDLen, len(l.KeysetID), "for key creation iteration %d", i)

			key, ok := keys[l.KeysetID]
			require.True(t, ok)
			require.Equal(t, key, someKey)
		}
	})
}
