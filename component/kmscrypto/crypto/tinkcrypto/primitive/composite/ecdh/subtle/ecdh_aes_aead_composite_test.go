package subtle

import (
	"encoding/json"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite"
	"github.com/stretchr/testify/require"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"github.com/tink-crypto/tink-go/v2/tink"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	mEncHelper, err := composite.NewRegisterCompositeAEADEncHelper(
		aead.AES256GCMKeyTemplate())
	require.NoError(t, err)

	cek := random.GetRandomBytes(uint32(32))
	cEnc := NewECDHAEADCompositeEncrypt(mEncHelper, cek)

	plaintext := []byte("secret message")
	aad := []byte("aad message")

	ciphertext, err := cEnc.Encrypt(plaintext, aad)
	require.NoError(t, err)

	dEnc := NewECDHAEADCompositeDecrypt(mEncHelper, cek)
	dpt, err := dEnc.Decrypt(ciphertext, aad)
	require.NoError(t, err)
	require.Equal(t, plaintext, dpt)
}

type MockEncHelper struct {
	AEADValue    tink.AEAD
	AEADErrValue error
	TagSizeValue int
	IVSizeValue  int
}

func (m *MockEncHelper) GetAEAD(symmetricHeyValue []byte) (tink.AEAD, error) {
	return m.AEADValue, m.AEADErrValue
}

func (m *MockEncHelper) GetTagSize() int {
	return m.TagSizeValue
}

func (m *MockEncHelper) GetIVSize() int {
	return m.IVSizeValue
}

func (m *MockEncHelper) BuildEncData(ct []byte) ([]byte, error) {
	tagSize := m.GetTagSize()
	ivSize := m.GetIVSize()
	iv := ct[:ivSize]
	ctAndTag := ct[ivSize:]
	tagOffset := len(ctAndTag) - tagSize

	encData := &composite.EncryptedData{
		Ciphertext: ctAndTag[:tagSize],
		IV:         iv,
		Tag:        ctAndTag[tagOffset:],
	}

	return json.Marshal(encData)
}

func (m *MockEncHelper) BuildDecData(encData *composite.EncryptedData) []byte {
	iv := encData.IV
	tag := encData.Tag
	ct := encData.Ciphertext
	finalCT := append(iv, ct...)
	finalCT = append(finalCT, tag...)

	return finalCT
}

func getAEADPrimitive(t *testing.T, kt *tinkpb.KeyTemplate) tink.AEAD {
	t.Helper()

	kh, err := keyset.NewHandle(kt)
	require.NoError(t, err)

	p, err := aead.New(kh)
	require.NoError(t, err)

	return p
}
