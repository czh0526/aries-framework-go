package middleware

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms/localkms"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/secretlock/noop"
	didmodel "github.com/czh0526/aries-framework-go/component/models/did"
	mockstorage "github.com/czh0526/aries-framework-go/component/storageutil/mock/storage"
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	mockvdr "github.com/czh0526/aries-framework-go/component/vdr/mock"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"
	"github.com/czh0526/aries-framework-go/pkg/internal/test/makemockdoc"
	"github.com/czh0526/aries-framework-go/pkg/store/connection"
	did_store "github.com/czh0526/aries-framework-go/pkg/store/did"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	spisecretlock "github.com/czh0526/aries-framework-go/spi/secretlock"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
	spivdr "github.com/czh0526/aries-framework-go/spi/vdr"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"testing"
)

const (
	defaultKID = "#key-1"
	oldDID     = "did:test:old"
	newDID     = "did:test:new"
	myDID      = "did:test:mine"
	theirDID   = "did:test:theirs"
)

func TestDIDCommMessageMiddleware_handleInboundRotate(t *testing.T) {

	t.Run("not didcomm v2", func(t *testing.T) {
		dr := createBlankDIDRotator(t)

		msg := service.DIDCommMsgMap{
			"@id":   "123456",
			"@type": "abc",
		}

		_, _, err := dr.handleInboundRotate(msg, "", "", nil)
		require.NoError(t, err)

		msg = service.DIDCommMsgMap{
			"foo": "123456",
			"bar": "abc",
		}

		err = dr.HandleInboundMessage(msg, "", "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "not a valid didcomm v1 or v2 message")
	})

	t.Run("bad from_prior", func(t *testing.T) {
		dr := createBlankDIDRotator(t)

		msg := service.DIDCommMsgMap{
			"id":         "`123456",
			"type":       "abc",
			"body":       map[string]interface{}{},
			"from_prior": []string{"abc", "def"},
		}

		_, _, err := dr.handleInboundRotate(msg, "", "", nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "field should be a string")

		msg = service.DIDCommMsgMap{
			"id":         "123456",
			"type":       "abc",
			"body":       map[string]interface{}{},
			"from_prior": "#$&@(*#^@(*#^",
		}

		_, _, err = dr.handleInboundRotate(msg, "", "", nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "parsing DID rotation JWS")
	})

	sender := createBlankDIDRotator(t)
	senderDoc := createMockDoc(t, sender, myDID)
	senderConnID := uuid.New().String()

	e := sender.connStore.SaveConnectionRecord(&connection.Record{
		ConnectionID: senderConnID,
		State:        connection.StateNameCompleted,
		TheirDID:     theirDID,
		MyDID:        myDID,
		Namespace:    connection.MyNSPrefix,
	})
	require.NoError(t, e)

	setResolveDocs(sender, []*didmodel.Doc{senderDoc})

	e = sender.RotateConnectionDID(senderConnID, defaultKID, newDID)
	require.NoError(t, e)

	senderConnRec, e := sender.connStore.GetConnectionRecord(senderConnID)
	require.NoError(t, e)

	blankMessage := service.DIDCommMsgMap{
		"id":   "123456",
		"type": "abc",
	}

	rotateMessage := sender.HandleOutboundMessage(blankMessage.Clone(), senderConnRec)

	t.Run("fail: can't rotate without prior connection", func(t *testing.T) {
		recip := createBlankDIDRotator(t)

		_, _, err := recip.handleInboundRotate(rotateMessage, newDID, theirDID, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "inbound message cannot rotate without an existing prior connection")
	})

	t.Run("fail: error reading connection record", func(t *testing.T) {
		recip := createBlankDIDRotator(t)

		connStore, err := connection.NewRecorder(&mockProvider{
			storeProvider: mockstorage.NewCustomMockStoreProvider(&mockstorage.MockStore{
				ErrQuery: fmt.Errorf("store error"),
				ErrGet:   fmt.Errorf("store error"),
			}),
		})
		require.NoError(t, err)

		recip.connStore = connStore
		_, _, err = recip.handleInboundRotate(rotateMessage, newDID, theirDID, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "looking up did rotation connection record")
	})

	t.Run("fail: from_prior JWS validation error", func(t *testing.T) {
		recip := createBlankDIDRotator(t)

		err := recip.connStore.SaveConnectionRecord(&connection.Record{
			ConnectionID: senderConnID,
			State:        connection.StateNameCompleted,
			TheirDID:     myDID,
			MyDID:        theirDID,
			Namespace:    connection.MyNSPrefix,
		})
		require.NoError(t, err)

		_, _, err = recip.handleInboundRotate(rotateMessage, newDID, theirDID, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "`from_prior` validation")
	})

	t.Run("fail: recipient rotated, but received message addressed to wrong DID", func(t *testing.T) {
		handler := createBlankDIDRotator(t)

		connRec := &connection.Record{
			ConnectionID: uuid.New().String(),
			State:        connection.StateNameCompleted,
			TheirDID:     myDID,
			MyDID:        theirDID,
			Namespace:    connection.MyNSPrefix,
			MyDIDRotation: &connection.DIDRotationRecord{
				OldDID:    "did:test:recipient-old",
				NewDID:    theirDID,
				FromPrior: "",
			},
		}

		_, _, err := handler.handleInboundRotateAck("did:oops:wrong", connRec)
		require.Error(t, err)
		require.Contains(t, err.Error(), "inbound message sent to unexpected DID")
	})

	t.Run("fail: error saving connection record", func(t *testing.T) {
		recip := createBlankDIDRotator(t)

		connID := uuid.New().String()

		connRec := &connection.Record{
			ConnectionID: connID,
			State:        connection.StateNameCompleted,
			TheirDID:     myDID,
			MyDID:        theirDID,
			Namespace:    connection.MyNSPrefix,
			MyDIDRotation: &connection.DIDRotationRecord{
				OldDID:    "did:test:recipient-old",
				NewDID:    theirDID,
				FromPrior: "",
			},
		}

		var err error

		mockStore := mockstorage.MockStore{
			Store: map[string]mockstorage.DBEntry{},
		}

		recip.connStore, err = connection.NewRecorder(&mockProvider{
			storeProvider: mockstorage.NewCustomMockStoreProvider(&mockStore),
		})
		require.NoError(t, err)

		err = recip.connStore.SaveConnectionRecord(connRec)
		require.NoError(t, err)

		mockStore.ErrPut = fmt.Errorf("store put error")

		err = recip.HandleInboundMessage(blankMessage, myDID, theirDID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "updating connection")
	})

	t.Run("success: pas-through, no rotation on either end", func(t *testing.T) {
		recip := createBlankDIDRotator(t)

		_, _, err := recip.handleInboundRotate(blankMessage, myDID, theirDID, nil)
		require.NoError(t, err)
	})
}

func createBlankDIDRotator(t *testing.T) *DIDCommMessageMiddleware {
	t.Helper()

	dr, err := New(createMockProvider(t))
	require.NoError(t, err)

	return dr
}

type mockProvider struct {
	kms           spikms.KeyManager
	crypto        spicrypto.Crypto
	storeProvider spistorage.Provider
	secretLock    spisecretlock.Service
	vdr           vdrapi.Registry
	mediaTypes    []string
	didStore      did_store.ConnectionStore
}

func (m *mockProvider) Crypto() spicrypto.Crypto {
	return m.crypto
}

func (m *mockProvider) KMS() spikms.KeyManager {
	return m.kms
}

func (m *mockProvider) VDRegistry() vdrapi.Registry {
	return m.vdr
}

func (m *mockProvider) StorageProvider() spistorage.Provider {
	return m.storeProvider
}

func (m *mockProvider) ProtocolStateStorageProvider() spistorage.Provider {
	return m.storeProvider
}

func (m *mockProvider) MediaTypeProfiles() []string {
	return m.mediaTypes
}

func (m *mockProvider) DIDConnectionStore() did_store.ConnectionStore {
	return m.didStore
}

type kmsProvider struct {
	kmsStore          spikms.Store
	secretLockService spisecretlock.Service
}

func (k *kmsProvider) StorageProvider() spikms.Store {
	return k.kmsStore
}

func (k *kmsProvider) SecretLock() spisecretlock.Service {
	return k.secretLockService
}

func createMockProvider(t *testing.T) *mockProvider {
	t.Helper()

	kmsStore, err := kms.NewAriesProviderWrapper(
		mockstorage.NewMockStoreProvider())
	require.NoError(t, err)

	kmsStorage, err := localkms.New(
		"local-lock://test/master/key/",
		&kmsProvider{
			kmsStore:          kmsStore,
			secretLockService: &noop.NoLock{},
		})
	require.NoError(t, err)

	cr, err := tinkcrypto.New()
	require.NoError(t, err)

	vdr := &mockvdr.VDRegistry{
		CreateFunc: func(didID string, doc *didmodel.Doc, option ...spivdr.DIDMethodOption) (*didmodel.DocResolution, error) {
			return nil, fmt.Errorf("not created")
		},
		ResolveFunc: func(didID string, opts ...spivdr.DIDMethodOption) (*didmodel.DocResolution, error) {
			return nil, fmt.Errorf("not found")
		},
	}

	didStore, err := did_store.NewConnectionStore(
		&mockProvider{
			storeProvider: mockstorage.NewMockStoreProvider(),
		})
	require.NoError(t, err)

	return &mockProvider{
		kms:           kmsStorage,
		crypto:        cr,
		vdr:           vdr,
		storeProvider: mockstorage.NewMockStoreProvider(),
		didStore:      didStore,
	}
}

func createMockDoc(t *testing.T, dr *DIDCommMessageMiddleware, docDID string) *didmodel.Doc {
	t.Helper()

	keyType := spikms.ECDSAP384TypeIEEEP1363

	return makemockdoc.MakeMockDoc(t, dr.kms, docDID, keyType)
}

func setResolveDocs(dr *DIDCommMessageMiddleware, docs []*didmodel.Doc) {
	dr.vdr = &mockvdr.VDRegistry{
		ResolveFunc: func(didID string, opts ...spivdr.DIDMethodOption) (*didmodel.DocResolution, error) {
			for _, doc := range docs {
				if didID == doc.ID {
					return &didmodel.DocResolution{
						DIDDocument: doc,
					}, nil
				}
			}

			return nil, vdrapi.ErrNotFound
		},
	}
}
