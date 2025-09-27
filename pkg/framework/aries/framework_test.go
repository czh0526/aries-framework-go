package aries

import (
	"fmt"
	mockcrypto "github.com/czh0526/aries-framework-go/component/kmscrypto/mock/crypto"
	mockkms "github.com/czh0526/aries-framework-go/component/kmscrypto/mock/kms"
	"github.com/czh0526/aries-framework-go/pkg/common/model"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/packer"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
	"github.com/czh0526/aries-framework-go/pkg/mock/didcomm"
	mockdiddoc "github.com/czh0526/aries-framework-go/pkg/mock/diddoc"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"testing"
)

func getServerPort(server net.Listener) int {
	return server.Addr().(*net.TCPAddr).Port
}

type mockInboundTransport struct {
	startError error
	stopError  error
}

func (m mockInboundTransport) Start(prov transport.Provider) error {
	if m.startError != nil {
		return m.startError
	}
	return nil
}

func (m mockInboundTransport) Stop() error {
	if m.stopError != nil {
		return m.stopError
	}

	return nil
}

func (m mockInboundTransport) Endpoint() string {
	return ""
}

var _ transport.InboundTransport = (*mockInboundTransport)(nil)

func startMockServer(t *testing.T, handler http.Handler) net.Listener {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() {
		err := http.Serve(listener, handler)
		if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			require.NoError(t, err)
		}
	}()

	return listener
}

type mockHTTPHandler struct{}

func (m mockHTTPHandler) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	if req.Body != nil {
		body, err := ioutil.ReadAll(req.Body)
		if err != nil || string(body) == "bad" {
			res.WriteHeader(http.StatusBadRequest)
			_, _ = res.Write([]byte(fmt.Sprintf("bad request: %s", body)))

			return
		}
	}

	res.WriteHeader(http.StatusAccepted)
	_, _ = res.Write([]byte("success"))
}

func TestFramework(t *testing.T) {
	t.Run("test framework - with no options", func(t *testing.T) {
		_, err := New()
		require.NoError(t, err)
	})

	t.Run("test framework new - with default outbound dispatcher", func(t *testing.T) {
		server := startMockServer(t, mockHTTPHandler{})
		port := getServerPort(server)
		defer func() {
			err := server.Close()
			if err != nil {
				t.Fatalf("failed to stop server: %v", err)
			}
		}()

		serverURL := fmt.Sprintf("http://localhost:%d", port)

		aries, err := New(
			WithInboundTransport(&mockInboundTransport{}),
			WithKMS(func(ctx spikms.Provider) (spikms.KeyManager, error) {
				return &mockkms.KeyManager{CreateKeyID: "abc"}, nil
			}),
			WithCrypto(&mockcrypto.Crypto{SignValue: []byte("mockValue")}),
			WithPacker(
				func(ctx packer.Provider) (packer.Packer, error) {
					return &didcomm.MockAuthCrypt{}, nil
				},
				func(ctx packer.Provider) (packer.Packer, error) {
					return &didcomm.MockAuthCrypt{}, nil
				},
			),
			WithMediaTypeProfiles([]string{"mockProfile"}))
		require.NoError(t, err)

		ctx, err := aries.Context()
		require.NoError(t, err)

		err = ctx.OutboundDispatcher().Send(
			[]byte("Hello World"),
			mockdiddoc.MockDIDKey(t),
			&service.Destination{ServiceEndpoint: model.NewDIDCommV1Endpoint(serverURL)})
		require.NoError(t, err)
	})

	t.Run("test KMS svc - with user provided instance", func(t *testing.T) {
		aries, err := New(
			WithInboundTransport(&mockInboundTransport{}),
			WithKMS(func(provider spikms.Provider) (spikms.KeyManager, error) {
				return &mockkms.KeyManager{CreateKeyID: "abc"}, nil
			}),
			WithCrypto(&mockcrypto.Crypto{SignValue: []byte("mockValue")}))
		require.NoError(t, err)
		require.NotEmpty(t, aries)

		ctx, err := aries.Context()
		require.NoError(t, err)

		v, err := ctx.Crypto().Sign(nil, "")
		require.NoError(t, err)
		require.Equal(t, []byte("mockValue"), v)
		err = aries.Close()
		require.NoError(t, err)
	})
}
