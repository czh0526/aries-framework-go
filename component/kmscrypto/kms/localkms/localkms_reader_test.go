package localkms

import (
	"github.com/stretchr/testify/require"
	"io"
	"testing"
)

func TestLocalKMSReader(t *testing.T) {
	someKey := []byte("someKeyData")
	someKeyID := "newKeyID"
	storeData := map[string][]byte{
		someKeyID: someKey,
	}

	t.Run("success case - create a valid storeReader with a non empty and stored keysetID", func(t *testing.T) {
		localStore := &inMemoryKMSStore{keys: storeData}

		l := newReader(localStore, someKeyID)
		require.NotEmpty(t, l)

		// 第一次读取，会构建 buf
		data := make([]byte, 512)
		n, err := l.Read(data)
		require.NoError(t, err)
		require.Equal(t, len(someKey), n)

		// 第二次读取，会使用之前的 buf 数据
		n, err = l.Read(data)
		require.EqualError(t, err, io.EOF.Error())
		require.Equal(t, n, 0)
	})

	t.Run("success case - create a valid storeReader with a very large keyset data", func(t *testing.T) {
		var veryLargeData []byte
		dataLen := 1000 * 1000
		blockSize := 512
		for i := 0; i < dataLen; i++ {
			veryLargeData = append(veryLargeData, byte(i))
		}

		mockStore := newInMemoryKMSStore()
		mockStore.keys[someKeyID] = veryLargeData

		l := newReader(mockStore, someKeyID)
		require.NotEmpty(t, l)
		data := make([]byte, blockSize)
		bytesRead := 0
		var readData []byte
		for bytesRead < dataLen-blockSize {
			n, err := l.Read(data)
			require.NoError(t, err)
			require.Equal(t, blockSize, n)

			bytesRead += n
			readData = append(readData, data...)
		}

		n, err := l.Read(data)
		require.NoError(t, err)
		readData = append(readData, data[:n]...)
		require.Equal(t, dataLen%blockSize, n)
		require.Equal(t, len(readData), dataLen)

		n, err = l.Read(data)
		require.EqualError(t, err, io.EOF.Error())
		require.Equal(t, n, 0)
	})
}
