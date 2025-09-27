package middleware

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/jwkkid"
	"github.com/czh0526/aries-framework-go/component/log"
	didmodel "github.com/czh0526/aries-framework-go/component/models/did"
	"github.com/czh0526/aries-framework-go/component/models/did/endpoint"
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	"github.com/czh0526/aries-framework-go/pkg/common/model"
	didcommservice "github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"
	"github.com/czh0526/aries-framework-go/pkg/doc/did"
	"github.com/czh0526/aries-framework-go/pkg/doc/jose"
	"github.com/czh0526/aries-framework-go/pkg/doc/util/vmparse"
	"github.com/czh0526/aries-framework-go/pkg/store/connection"
	conn_store "github.com/czh0526/aries-framework-go/pkg/store/connection"
	did_store "github.com/czh0526/aries-framework-go/pkg/store/did"
	"github.com/czh0526/aries-framework-go/pkg/vdr/peer"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
	"github.com/google/uuid"
	"time"
)

var logger = log.New("didcomm/common/middleware")

const (
	fromPriorJSONKey  = "from_prior"
	fromDIDJSONKey    = "from"
	bodyJSONKey       = "body"
	initialStateParam = "initialState"
)

type DIDCommMessageMiddleware struct {
	kms               spikms.KeyManager
	crypto            spicrypto.Crypto
	vdr               vdrapi.Registry
	connStore         *conn_store.Recorder
	didStore          did_store.ConnectionStore
	mediaTypeProfiles []string
}

type rotatePayload struct {
	Sub string `json:"sub"`
	ISS string `json:"iss"`
	IAT int64  `json:"iat"`
}

type provider interface {
	Crypto() spicrypto.Crypto
	KMS() spikms.KeyManager
	VDRegistry() vdrapi.Registry
	StorageProvider() spistorage.Provider
	ProtocolStateStorageProvider() spistorage.Provider
	MediaTypeProfiles() []string
	DIDConnectionStore() did_store.ConnectionStore
}

func New(p provider) (*DIDCommMessageMiddleware, error) {
	connRecorder, err := connection.NewRecorder(p)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize connection recorder: %w", err)
	}

	return &DIDCommMessageMiddleware{
		kms:               p.KMS(),
		crypto:            p.Crypto(),
		vdr:               p.VDRegistry(),
		connStore:         connRecorder,
		mediaTypeProfiles: p.MediaTypeProfiles(),
		didStore:          p.DIDConnectionStore(),
	}, nil
}

func (h *DIDCommMessageMiddleware) HandleOutboundMessage(msg didcommservice.DIDCommMsgMap,
	rec *connection.Record) didcommservice.DIDCommMsgMap {
	if rec.PeerDIDInitialState != "" {
		msg[fromDIDJSONKey] = rec.MyDID + "?" + initialStateParam + "=" + rec.PeerDIDInitialState
	}

	if isV2, err := didcommservice.IsDIDCommV2(&msg); !isV2 || err != nil {
		return msg
	}

	if _, ok := msg[fromDIDJSONKey]; !ok {
		msg[fromDIDJSONKey] = rec.MyDID
	}

	if _, ok := msg[bodyJSONKey]; !ok {
		msg[bodyJSONKey] = map[string]interface{}{}
	}

	if rec.MyDIDRotation != nil {
		msg[fromPriorJSONKey] = rec.MyDIDRotation.FromPrior
	}

	return msg
}

func (h *DIDCommMessageMiddleware) HandleInboundMessage(
	msg didcommservice.DIDCommMsgMap, theirDID, myDID string) error {
	rec, err := h.handleInBoundInvitationAcceptance(theirDID, myDID)
	if err != nil {
		return err
	}

	isV2, err := didcommservice.IsDIDCommV2(&msg)
	if !isV2 || err != nil {
		return err
	}

	var updatedConnRec bool

	rec2, stepUpdated, err := h.handleInboundRotate(msg, theirDID, myDID, rec)
	if err != nil {
		return err
	}

	updatedConnRec = updatedConnRec || stepUpdated
	if rec2 != nil {
		rec = rec2
	}

	if rec == nil {
		rec, err = h.connStore.GetConnectionRecordByTheirDID(theirDID)
		if err != nil {
			return err
		}
	}

	rec2, stepUpdated, err = h.handleInboundRotateAck(myDID, rec)
	if err != nil {
		return err
	}

	updatedConnRec = updatedConnRec || stepUpdated
	if rec2 != nil {
		rec = rec2
	}

	if rec != nil && rec.PeerDIDInitialState != "" && myDID == rec.MyDID {
		rec.PeerDIDInitialState = ""
		updatedConnRec = true
	}

	if updatedConnRec && rec != nil {
		err = h.connStore.SaveConnectionRecord(rec)
		if err != nil {
			return fmt.Errorf("updating connection: %w", err)
		}
	}

	return nil
}

type invitationStub struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

func (h *DIDCommMessageMiddleware) handleInBoundInvitationAcceptance(senderDID, recipientDID string) (
	*connection.Record, error) {
	didParsed, err := didmodel.Parse(recipientDID)
	if err != nil {
		logger.Warnf("failed to parse inbound recipient DID: %s", err.Error())
		return nil, nil
	}

	if didParsed.Method == peer.DIDMethod {
		return nil, nil
	}

	inv := &invitationStub{}

	err = h.connStore.GetOOBv2Invitation(recipientDID, inv)
	if errors.Is(err, spistorage.ErrDataNotFound) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	rec, err := h.connStore.GetConnectionRecordByDIDs(recipientDID, senderDID)
	if err == nil {
		return rec, nil
	} else if !errors.Is(err, spistorage.ErrDataNotFound) {
		return rec, fmt.Errorf("failed to get connection record: %w", err)
	}

	rec = &connection.Record{
		ConnectionID:    uuid.New().String(),
		MyDID:           recipientDID,
		TheirDID:        senderDID,
		InvitationID:    inv.ID,
		State:           connection.StateNameCompleted,
		Namespace:       connection.MyNSPrefix,
		ServiceEndPoint: model.NewDIDCommV2Endpoint([]endpoint.DIDCommV2Endpoint{{Accept: h.mediaTypeProfiles}}),
		DIDCommVersion:  didcommservice.V2,
	}

	err = h.connStore.SaveConnectionRecord(rec)
	if err != nil {
		return nil, fmt.Errorf("failed to save new connection record: %w", err)
	}

	return rec, nil
}

func (h *DIDCommMessageMiddleware) handleInboundRotate(
	msg didcommservice.DIDCommMsgMap, senderDID, recipientDID string,
	recIn *connection.Record) (*connection.Record, bool, error) {

	var (
		jws            *jose.JSONWebSignature
		payload        *rotatePayload
		err            error
		alreadyRotated bool
		updatedConnRec bool
	)

	fromPriorInterface, theyRotate := msg[fromPriorJSONKey]
	if !theyRotate {
		return recIn, false, nil
	}

	fromPrior, ok := fromPriorInterface.(string)
	if !ok {
		return nil, false, fmt.Errorf("didcomm message 'from_prior' field should be a string")
	}

	jws, payload, err = h.getUnverifiedJWS(senderDID, fromPrior)
	if err != nil {
		return nil, false, err
	}

	theirOldDID := payload.ISS
	theirNewDID := payload.Sub

	rec, err := h.connStore.GetConnectionRecordByDIDs(recipientDID, theirOldDID)
	if err != nil {
		_, err = h.connStore.GetConnectionRecordByDIDs(recipientDID, theirNewDID)
		if err == nil {
			alreadyRotated = true
		}
	}

	if errors.Is(err, spistorage.ErrDataNotFound) {
		return nil, false, fmt.Errorf("inbound message cannot rotate without an existing prior connection")
	} else if err != nil {
		return nil, false, fmt.Errorf("looking up did rotation connection record: %w", err)
	}

	if !alreadyRotated {
		err = h.verifyJWSAndPayload(jws, payload)
		if err != nil {
			return nil, false, fmt.Errorf("'from_prior' verification failed: %w", err)
		}

		rec.TheirDID = payload.Sub
		updatedConnRec = true
	}

	if rec != nil {
		recIn = rec
	}

	return recIn, updatedConnRec, nil
}

func (h *DIDCommMessageMiddleware) handleInboundRotateAck(recipientDID string, rec *connection.Record) (
	*connection.Record, bool, error) {
	var updatedConnRec bool

	if rec.MyDIDRotation != nil {
		switch recipientDID {
		case rec.MyDIDRotation.OldDID:

		case rec.MyDIDRotation.NewDID:
			rec.MyDIDRotation = nil
			updatedConnRec = true

		default:
			return nil, false, fmt.Errorf("inbound message sent to unexpected DID")
		}
	}

	return rec, updatedConnRec, nil
}

func (h *DIDCommMessageMiddleware) getUnverifiedJWS(senderDID, fromPrior string) (
	*jose.JSONWebSignature, *rotatePayload, error) {
	skipVerify := jose.SignatureVerifirFunc(func(_ jose.Headers, _, _, _ []byte) error {
		return nil
	})

	jws, err := jose.ParseJWS(fromPrior, skipVerify)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing DID rotation JWS: %w", err)
	}

	payload := rotatePayload{}
	err = json.Unmarshal(jws.Payload, &payload)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing DID rotation payload: %w", err)
	}

	if payload.ISS == "" || payload.Sub == "" {
		return nil, nil, fmt.Errorf("from_prior payload missing iss or sub, both are required")
	}

	if senderDID != payload.Sub {
		return nil, nil, fmt.Errorf("from_prior payload sub must be the DID of the message sender")
	}

	return jws, &payload, nil
}

func (h *DIDCommMessageMiddleware) RotateConnectionDID(connectionID, signingKID, newDID string) error {
	record, err := h.connStore.GetConnectionRecord(connectionID)
	if err != nil {
		return fmt.Errorf("getting connection record: %w", err)
	}

	oldDID := record.MyDID

	oldDocRes, err := h.vdr.Resolve(oldDID)
	if err != nil {
		return fmt.Errorf("resolving my DID: %w", err)
	}

	fromPrior, err := h.Create(oldDocRes.DIDDocument, signingKID, newDID)
	if err != nil {
		return fmt.Errorf("creating did rotation from_prior: %w", err)
	}

	record.MyDIDRotation = &connection.DIDRotationRecord{
		NewDID:    newDID,
		OldDID:    oldDID,
		FromPrior: fromPrior,
	}

	didParsed, err := didmodel.Parse(newDID)
	if err != nil {
		return fmt.Errorf("parsing new DID: %w", err)
	}

	if didParsed.Method == peer.DIDMethod {
		newDoc, e := h.vdr.Resolve(newDID)
		if e != nil {
			return fmt.Errorf("resolving new DID: %w", e)
		}

		initialState, e := peer.UnsignedGenesisDelta(newDoc.DIDDocument)
		if e != nil {
			return fmt.Errorf("generating peer DID initialState for new DID: %w", e)
		}

		record.PeerDIDInitialState = initialState
	}

	record.MyDID = newDID

	err = h.connStore.SaveConnectionRecord(record)
	if err != nil {
		return fmt.Errorf("saving connection record under my new DID: %w", err)
	}

	record.MyDID = oldDID
	record.ConnectionID = uuid.New().String()

	err = h.connStore.SaveConnectionRecord(record)
	if err != nil {
		return fmt.Errorf("saving connection record under my old DID: %w", err)
	}

	return nil
}

func (h *DIDCommMessageMiddleware) verifyJWSAndPayload(jws *jose.JSONWebSignature, payload *rotatePayload) error {
	oldKID, ok := jws.ProtectedHeaders.KeyID()
	if !ok {
		return fmt.Errorf("from_prior protected headers missing KID")
	}

	oldDocRes, err := h.vdr.Resolve(payload.ISS)
	if err != nil {
		return fmt.Errorf("resolving prior DID doc: %w", err)
	}

	vm, found := did.LookupPublicKey(oldKID, oldDocRes.DIDDocument)
	if !found {
		return fmt.Errorf("kid not found in doc")
	}

	keyBytes, kty, _, err := vmparse.VMToBytesTypeCrv(vm)
	if err != nil {
		return err
	}

	pubKH, err := h.kms.PubKeyBytesToHandle(keyBytes, kty)
	if err != nil {
		return fmt.Errorf("get verification key handle: %w", err)
	}

	verify := jose.DefaultSigningInputVerifier(
		func(joseHeaders jose.Headers, payload, signingInput, signature []byte) error {
			return h.crypto.Verify(signature, signingInput, pubKH)
		})

	err = verify.Verify(jws.ProtectedHeaders, jws.Payload, nil, jws.Signature())
	if err != nil {
		return fmt.Errorf("signature verification: %w", err)
	}

	return nil
}

func (h *DIDCommMessageMiddleware) Create(oldDoc *didmodel.Doc, oldKID, newDID string) (string, error) {
	payload := rotatePayload{
		Sub: newDID,
		ISS: oldDoc.ID,
		IAT: time.Now().Unix(),
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshalling did rotate payload: %w", err)
	}

	vm, found := didmodel.LookupPublicKey(oldKID, oldDoc)
	if !found {
		return "", fmt.Errorf("sender KID not found in doc provided")
	}

	keyBytes, kty, crv, err := vmparse.VMToBytesTypeCrv(vm)
	if err != nil {
		return "", err
	}

	kmsKID, err := jwkkid.CreateKID(keyBytes, kty)
	if err != nil {
		return "", fmt.Errorf("get signing key KMS KID: %w", err)
	}

	kh, err := h.kms.Get(kmsKID)
	if err != nil {
		return "", fmt.Errorf("get signing key handle: %w", err)
	}

	var alg string

	if vm.Type == ed25519VerificationKey2018 {
		alg = "EdDSA"
	} else if vm.Type == jsonWebKey2020 {
		jwkKey := vm.JSONWebKey()
		alg = jwkKey.Algorithm
	}

	protected := jose.Headers(map[string]interface{}{
		"typ": "JWT",
		"alg": alg,
		"crv": crv,
		"kid": oldKID,
	})

	jws, err := jose.NewJWS(protected, nil, payloadBytes,
		&cryptoSigner{
			kh:     kh,
			crypto: h.crypto,
		})
	if err != nil {
		return "", fmt.Errorf("creating DID rotation JWS: %w", err)
	}

	return jws.SerializeCompact(false)
}

type cryptoSigner struct {
	kh     interface{}
	crypto spicrypto.Crypto
}

func (c *cryptoSigner) Sign(data []byte) ([]byte, error) {
	return c.crypto.Sign(data, c.kh)
}

func (c *cryptoSigner) Headers() jose.Headers {
	return nil
}

const (
	jsonWebKey2020             = "JsonWebKey2020"
	ed25519VerificationKey2018 = "Ed25519VerificationKey2018"
)
