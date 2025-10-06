package peer

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	didmodel "github.com/czh0526/aries-framework-go/component/models/did"
	"time"
)

func (V VDR) Close() error {
	return nil
}

type modifiedBy struct {
	Key string `json:"key,omitempty"`
	Sig string `json:"sig,omitempty"`
}

type docDelta struct {
	Change     string        `json:"change,omitempty"`
	ModifiedBy *[]modifiedBy `json:"by,omitempty"`
	ModifiedAt time.Time     `json:"when,omitempty"`
}

func genesisDeltaBytes(doc *didmodel.Doc, by *[]modifiedBy) ([]byte, error) {
	var deltas []docDelta

	jsonDoc, err := doc.JSONBytes()
	if err != nil {
		return nil, fmt.Errorf("JSON marshalling of document failed: %w", err)
	}

	docDelta := &docDelta{
		Change:     base64.URLEncoding.EncodeToString(jsonDoc),
		ModifiedBy: by,
		ModifiedAt: time.Now(),
	}

	deltas = append(deltas, *docDelta)

	val, err := json.Marshal(deltas)
	if err != nil {
		return nil, fmt.Errorf("JSON marshalling of document deltas failed: %w", err)
	}

	return val, nil
}

func UnsignedGenesisDelta(doc *didmodel.Doc) (string, error) {
	peerDeltaBytes, err := genesisDeltaBytes(doc, nil)
	if err != nil {
		return "", fmt.Errorf("failed to generate peer DID initialState: %w", err)
	}

	peerDeltaB64 := base64.RawURLEncoding.EncodeToString(peerDeltaBytes)

	return peerDeltaB64, nil
}
