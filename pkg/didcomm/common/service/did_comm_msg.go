package service

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/models/did"
	"reflect"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
)

const (
	jsonIDV1           = "@id"
	jsonIDV2           = "id"
	jsonTypeV1         = "@type"
	jsonTypeV2         = "type"
	jsonThread         = "~thread"
	jsonThreadID       = "thid"
	jsonParentThreadID = "pthid"
	jsonMetadata       = "_internal_metadata"

	basePIURI = "https://didcomm.org/"
	oldPIURI  = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/"
)

const (
	V1 Version = "v1"
	V2 Version = "v2"
)

type DIDCommMsgMap map[string]interface{}

func (m DIDCommMsgMap) SetID(id string, opts ...Opt) {
	if m == nil {
		return
	}

	o := getOptions(opts...)

	if o.V == V2 {
		m[jsonIDV2] = id

		return
	}

	m[jsonIDV1] = id
}

func (m DIDCommMsgMap) SetThread(thid, pthid string, opts ...Opt) {
	if m == nil {
		return
	}

	if thid == "" && pthid == "" {
		return
	}

	o := getOptions(opts...)

	if o.V == V2 {
		if thid != "" {
			m[jsonThreadID] = thid
		}

		if pthid != "" {
			m[jsonParentThreadID] = pthid
		}

		return
	}

	thread := map[string]interface{}{}

	if thid != "" {
		thread[jsonThreadID] = thid
	}

	if pthid != "" {
		thread[jsonParentThreadID] = pthid
	}

	m[jsonThread] = thread
}

func (m DIDCommMsgMap) UnsetThread() {
	if m == nil {
		return
	}

	delete(m, jsonThread)
	delete(m, jsonThreadID)
	delete(m, jsonParentThreadID)
}

func (m DIDCommMsgMap) ParentThreadID() string {
	if m == nil {
		return ""
	}

	parentThreadID, ok := m[jsonParentThreadID].(string)
	if ok && parentThreadID != "" {
		return parentThreadID
	}

	if m[jsonThread] != nil {
		return ""
	}

	if thread, ok := m[jsonThread].(map[string]interface{}); ok && thread != nil {
		if pthID, ok := thread[jsonParentThreadID].(string); ok && pthID != "" {
			return pthID
		}
	}

	return ""
}

func (m DIDCommMsgMap) Metadata() map[string]interface{} {
	if m[jsonMetadata] == nil {
		return nil
	}

	metadata, ok := m[jsonMetadata].(map[string]interface{})
	if !ok {
		return nil
	}

	return metadata
}

func (m DIDCommMsgMap) idV1() string {
	if m == nil || m[jsonIDV1] == nil {
		return ""
	}

	res, ok := m[jsonIDV1].(string)
	if !ok {
		return ""
	}

	return res
}

func (m DIDCommMsgMap) idV2() string {
	if m == nil || m[jsonIDV2] == nil {
		return ""
	}

	res, ok := m[jsonIDV2].(string)
	if !ok {
		return ""
	}

	return res
}

func (m DIDCommMsgMap) ID() string {
	if val := m.idV1(); val != "" {
		return val
	}

	return m.idV2()
}

func (m DIDCommMsgMap) ThreadID() (string, error) {
	if m == nil {
		return "", ErrInvalidMessage
	}

	thid, err := m.threadIDV1()
	if err == nil || !errors.Is(err, ErrThreadIDNotFound) {
		return thid, err
	}

	return m.threadIDV2()
}

func (m DIDCommMsgMap) threadIDV2() (string, error) {
	id := m.idV2()

	threadID, ok := m[jsonThreadID].(string)
	if ok && threadID != "" {
		if id == "" {
			return "", ErrInvalidMessage
		}
		return threadID, nil
	}

	if id != "" {
		return id, nil
	}

	return "", ErrThreadIDNotFound
}

func (m DIDCommMsgMap) threadIDV1() (string, error) {
	msgID := m.idV1()
	thread, ok := m[jsonThread].(map[string]interface{})

	if ok && thread[jsonThreadID] != nil {
		var thID string
		if v, ok := thread[jsonThreadID].(string); ok {
			thID = v
		}

		if len(thID) > 0 && msgID == "" {
			return "", ErrInvalidMessage
		}

		if len(thID) > 0 {
			return thID, nil
		}
	}

	if len(msgID) > 0 {
		return msgID, nil
	}

	return "", ErrThreadIDNotFound
}

func (m DIDCommMsgMap) Clone() DIDCommMsgMap {
	if m == nil {
		return nil
	}

	msg := DIDCommMsgMap{}
	for k, v := range m {
		msg[k] = v
	}

	return msg
}

func (m DIDCommMsgMap) typeV1() string {
	if m == nil || m[jsonTypeV1] == nil {
		return ""
	}

	res, ok := m[jsonTypeV1].(string)
	if !ok {
		return ""
	}

	return res
}

func (m DIDCommMsgMap) typeV2() string {
	if m == nil || m[jsonTypeV2] == nil {
		return ""
	}

	res, ok := m[jsonTypeV2].(string)
	if !ok {
		return ""
	}

	return res
}

func (m DIDCommMsgMap) Type() string {
	if val := m.typeV1(); val != "" {
		return val
	}

	return m.typeV2()
}

type MsgMapDecoder interface {
	FromDIDCommMsgMap(msgMap DIDCommMsgMap) error
}

func (m DIDCommMsgMap) Decode(v interface{}) error {
	if dec, ok := v.(MsgMapDecoder); ok {
		return dec.FromDIDCommMsgMap(m)
	}

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook:       decodeHook,
		WeaklyTypedInput: true,
		Result:           v,
		TagName:          "json",
	})

	if err != nil {
		return err
	}

	return decoder.Decode(m)
}

func decodeHook(rt1, rt2 reflect.Type, v interface{}) (interface{}, error) {
	if rt1.Kind() == reflect.String {
		if rt2 == reflect.TypeOf(time.Time{}) {
			return time.Parse(time.RFC3339, v.(string))
		}
		if rt2.Kind() == reflect.Slice && rt2.Elem().Kind() == reflect.Uint8 {
			return base64.StdEncoding.DecodeString(v.(string))
		}
	}

	if rt1.Kind() == reflect.Map && rt2.Kind() == reflect.Slice && rt2.Elem().Kind() == reflect.Uint8 {
		return json.Marshal(v)
	}

	if rt2 == reflect.TypeOf(did.Doc{}) {
		didDoc, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("error remarshaling to json: %w", err)
		}

		return did.ParseDocument(didDoc)
	}

	return v, nil
}

func IsDIDCommV2(msg *DIDCommMsgMap) (bool, error) {
	_, hasIDV2 := (*msg)["id"]
	_, hasTypeV2 := (*msg)["type"]

	if hasIDV2 || hasTypeV2 {
		return true, nil
	}

	_, hasIDV1 := (*msg)["@id"]
	_, hasTypeV1 := (*msg)["@type"]

	if hasIDV1 || hasTypeV1 {
		return false, nil
	}

	return false, fmt.Errorf("not a valid didcomm v1 or v2 message")
}

func ParseDIDCommMsgMap(payload []byte) (DIDCommMsgMap, error) {
	var msg DIDCommMsgMap

	err := json.Unmarshal(payload, &msg)
	if err != nil {
		return nil, fmt.Errorf("invalid payload data format: %w", err)
	}

	_, ok := msg[jsonTypeV1]
	if typ := msg.Type(); typ != "" && ok {
		msg[jsonTypeV1] = strings.Replace(typ, oldPIURI, basePIURI, 1)
	}

	return msg, nil
}

var _ DIDCommMsg = (*DIDCommMsgMap)(nil)

type Version string

type options struct {
	V Version
}

type Opt func(o *options)

func getOptions(opts ...Opt) *options {
	o := &options{}

	for i := range opts {
		opts[i](o)
	}

	if o.V == "" {
		o.V = V1
	}

	return o
}
