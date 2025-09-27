package internal

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
	mockpackager "github.com/czh0526/aries-framework-go/pkg/mock/didcomm/packager"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestUnpackMessage(t *testing.T) {
	msgB64 := base64.StdEncoding.EncodeToString([]byte("msg"))
	msgB64Raw := base64.RawURLEncoding.EncodeToString([]byte("msgraw1"))

	tests := []struct {
		name    string
		packer  transport.Packager
		message []byte
		source  string
	}{
		{
			name:    "success unpack",
			packer:  &mockpackager.Packager{UnpackValue: &transport.Envelope{}},
			message: []byte(""),
			source:  "http",
		},
		{
			name:    "error unpack not double quoted",
			packer:  &mockpackager.Packager{UnpackErr: errors.New("unpack error")},
			message: []byte("not double quote"),
			source:  "http",
		},
		{
			name:    "success unpack double quoted message",
			packer:  &mockpackager.Packager{UnpackValue: &transport.Envelope{}},
			message: []byte(fmt.Sprintf("\"%v\"", msgB64)),
			source:  "ws",
		},
		{
			name:    "success unpack double quoted message RawBase64URL encoded",
			packer:  &mockpackager.Packager{UnpackValue: &transport.Envelope{}},
			message: []byte(fmt.Sprintf("\"%v\"", msgB64Raw)),
			source:  "ws",
		},
		{
			name:    "error unpack double quoted invalid base64 encoded message",
			packer:  &mockpackager.Packager{UnpackErr: fmt.Errorf("failed to unpack")},
			message: []byte(fmt.Sprintf("\"%v\"", "!!!!!!!")),
			source:  "ws",
		},
		{
			name:    "error in unpack call",
			packer:  &mockpackager.Packager{UnpackErr: fmt.Errorf("failed to unpack")},
			message: []byte(fmt.Sprintf("\"%v\"", msgB64)),
			source:  "ws",
		},
	}

	for _, tt := range tests {
		tc := tt
		t.Run(tc.name, func(t *testing.T) {
			e, err := UnpackMessage(tc.message, tc.packer, tc.source)
			if strings.HasPrefix(tc.name, "success") {
				require.NoError(t, err)
				require.NotNil(t, e)

				return
			}

			switch tc.name {
			case "error unpack not double quoted":
				require.EqualError(t, err, "failed to unpack msg from http: unpack error")
			case "error unpack double quoted invalid base64 encoded message":
				require.Error(t, err)
			case "error in unpack call":
				require.EqualError(t, err, "failed to unpack msg from ws: failed to unpack")
			}

			require.Empty(t, e)
		})
	}
}
