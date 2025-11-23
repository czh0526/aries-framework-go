package command

import (
	"encoding/json"
	spilog "github.com/czh0526/aries-framework-go/spi/log"
	"io"
)

func WriteNillableResponse(w io.Writer, v interface{}, l spilog.Logger) {
	obj := v
	if v == nil {
		obj = map[string]interface{}{}
	}

	if err := json.NewEncoder(w).Encode(obj); err != nil {
		l.Errorf("Unable to send error response, %s", err)
	}
}
