package service

import (
	"errors"
	"fmt"
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
)

type Version string

const (
	V1 Version = "v1"
	V2 Version = "v2"
)

type options struct {
	V Version
}

type Opt func(o *options)

type DIDCommMsgMap map[string]interface{}

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
