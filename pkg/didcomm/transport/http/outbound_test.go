package http

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/czh0526/aries-framework-go/pkg/common/model"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestWithOutboundOpts(t *testing.T) {
	opt := WithOutboundHTTPClient(nil)
	require.NotNil(t, opt)

	clOpts := &outboundCommHTTPOpts{}
	opt(clOpts)

	opt = WithOutboundTimeout(clientTimeout)
	require.NotNil(t, opt)

	clOpts = &outboundCommHTTPOpts{}
	require.Panics(t, func() {
		opt(clOpts)
	})
}

func TestOutboundHTTPTransport(t *testing.T) {
	server := startMockServer(mockHTTPHandler{})

	port := getServerPort(server)
	serverURL := fmt.Sprintf("http://localhost:%d", port)

	defer func() {
		err := server.Close()
		if err != nil {
			t.Fatalf("failed to close mock http server: %v", err)
		}
	}()

	cp := x509.NewCertPool()
	err := addCertsToCertPool(cp)
	require.NoError(t, err)

	tlsConfig := &tls.Config{
		RootCAs:      cp,
		Certificates: nil,
	}

	_, err = NewOutbound()
	require.Error(t, err)
	require.EqualError(t, err, "creation of outbound transport requires an HTTP client")

	ot, err := NewOutbound(WithOutboundTLSConfig(tlsConfig), WithOutboundTimeout(clientTimeout))
	require.NoError(t, err)
	require.NotNil(t, ot)

	r, e := ot.Send([]byte("hello world"), prepareDestination("serverURL"))
	require.Error(t, e)
	require.Empty(t, r)

	r, e = ot.Send([]byte("hello world"), prepareDestination("https://badurl"))
	require.Error(t, e)
	require.Empty(t, r)

	r, e = ot.Send([]byte("bad"), prepareDestination(serverURL))
	require.Error(t, e)
	require.Empty(t, r)
	require.Contains(t, e.Error(), "received unsuccessful POST HTTP status from agent")

	r, e = ot.Send([]byte("hello world"), prepareDestination(serverURL))
	require.NoError(t, e)
	require.NotEmpty(t, r)

	require.True(t, ot.Accept("http://example.com"))
	require.False(t, ot.Accept("123:22"))
}

func prepareDestination(endpoint string) *service.Destination {
	return &service.Destination{
		ServiceEndpoint: model.NewDIDCommV1Endpoint(endpoint),
	}
}
