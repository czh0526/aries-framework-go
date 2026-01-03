package defaults

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport/http"
	"github.com/czh0526/aries-framework-go/pkg/framework/aries"
)

func WithInboundHTTPAddr(internalAddr, externalAddr, certFile, keyFile string) aries.Option {
	return func(opts *aries.Aries) error {
		inbound, err := http.NewInbound(internalAddr, externalAddr, certFile, keyFile)
		if err != nil {
			return fmt.Errorf("http inbound transport initialization failed: %w", err)
		}
		return aries.WithInboundTransport(inbound)(opts)
	}
}
