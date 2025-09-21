package http

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
	mockpackager "github.com/czh0526/aries-framework-go/pkg/mock/didcomm/packager"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"net"
	"net/http"
	"testing"
	"time"
)

type mockProvider struct {
	packagerValue transport.Packager
}

func (m *mockProvider) InboundMessageHandler() transport.InboundMessageHandler {
	return func(envelope *transport.Envelope) error {
		logger.Debugf("mesage received is %s", envelope.Message)
		return nil
	}
}

func (m *mockProvider) Packager() transport.Packager {
	return m.packagerValue
}

func (m *mockProvider) AriesFrameworkID() string {
	return "aries-framework-instance-1"
}

var _ transport.Provider = (*mockProvider)(nil)

func TestInboundHandler(t *testing.T) {
	inHandler, err := NewInboundHandler(nil)
	require.Error(t, err)
	require.Nil(t, inHandler)

	mockPackager := &mockpackager.Packager{
		UnpackValue: &transport.Envelope{
			Message: []byte("data"),
		},
	}

	inHandler, err = NewInboundHandler(&mockProvider{
		packagerValue: mockPackager,
	})
	require.NoError(t, err)
	require.NotNil(t, inHandler)

	server := startMockServer(inHandler)
	port := getServerPort(server)
	serverURL := fmt.Sprintf("https://localhost:%d", port)

	defer func() {
		e := server.Close()
		if e != nil {
			t.Fatalf("Faild to stop server: %s", e)
		}
	}()

	cp := x509.NewCertPool()
	err = addCertsToCertPool(cp)
	require.NoError(t, err)

	tlsConfig := &tls.Config{
		RootCAs:      cp,
		Certificates: nil,
	}

	client := http.Client{
		Timeout: clientTimeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	rs, err := client.Get(serverURL + "/")
	require.NoError(t, err)
	err = rs.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusMethodNotAllowed, rs.StatusCode)

	rs, err = client.Post(serverURL+"/", "bad-content-type", bytes.NewBuffer([]byte("Hello World")))
	require.NoError(t, err)
	err = rs.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusUnsupportedMediaType, rs.StatusCode)

	contentTypes := []string{commContentType, commContentTypeLegacy}
	data := "success"

	for _, contentType := range contentTypes {
		resp, err := client.Post(serverURL+"/", contentType, nil)
		require.NoError(t, err)
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		require.NoError(t, resp.Body.Close())

		resp, err = client.Post(serverURL+"/", contentType, bytes.NewBuffer([]byte(data)))
		require.NoError(t, err)
		err = resp.Body.Close()
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, http.StatusAccepted, resp.StatusCode)
	}

	mockPackager.UnpackValue = nil
	mockPackager.UnpackErr = fmt.Errorf("unpack error")

	for _, contentType := range contentTypes {
		resp, err := client.Post(serverURL+"/", contentType, bytes.NewBuffer([]byte(data)))
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
		body, err := ioutil.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Contains(t, string(body), "failed to unpack msg")
		require.NoError(t, resp.Body.Close())
	}
}

func TestInboundTransport(t *testing.T) {
	t.Run("test inbound transport - with host/port", func(t *testing.T) {
		port := "26601"
		externalAddr := "http://example.com:" + port
		inbound, err := NewInbound("localhost:"+port, externalAddr, "", "")
		require.NoError(t, err)
		require.Equal(t, externalAddr, inbound.Endpoint())
	})

	t.Run("test inbound transport - with host/port, no external address", func(t *testing.T) {
		internalAddr := "example.com:26602"
		inbound, err := NewInbound(internalAddr, "", "", "")
		require.NoError(t, err)
		require.Equal(t, internalAddr, inbound.Endpoint())
	})

	t.Run("test inbound transport - invoke endpoint", func(t *testing.T) {
		inbound, err := NewInbound("localhost:26605", "", "", "")
		require.NoError(t, err)
		require.NotEmpty(t, inbound)

		mockPackager := &mockpackager.Packager{
			UnpackValue: &transport.Envelope{
				Message: []byte("data"),
			},
		}
		err = inbound.Start(&mockProvider{packagerValue: mockPackager})
		require.NoError(t, err)
		require.NoError(t, listenFor("localhost:26605", time.Second))

		contentTypes := []string{commContentType, commContentTypeLegacy}
		client := http.Client{}

		for _, contentType := range contentTypes {
			var resp *http.Response
			resp, err = client.Post("http://localhost:26605/", contentType, bytes.NewBuffer([]byte("success")))
			require.NoError(t, err)
			require.Equal(t, http.StatusAccepted, resp.StatusCode)
			require.NotNil(t, resp)

			err = resp.Body.Close()
			require.NoError(t, err)
		}

		err = inbound.Stop()
		require.NoError(t, err)

		for _, contentType := range contentTypes {
			_, err = client.Post("http://localhost:26605/", contentType, bytes.NewBuffer([]byte("success")))
			require.Error(t, err)
		}
	})
}

func listenFor(host string, d time.Duration) error {
	timeout := time.After(d)

	i := 0
	for {
		i++
		select {
		case <-timeout:
		default:
			conn, err := net.Dial("tcp", host)
			if err != nil {
				continue
			}

			fmt.Printf("connection established %d \n", i)
			return conn.Close()
		}
	}
}
