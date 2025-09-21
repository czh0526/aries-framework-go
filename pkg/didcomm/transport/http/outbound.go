package http

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
	"net/http"
	"strings"
	"time"
)

const (
	commContentType       = "application/didcomm-envelope-enc"
	commContentTypeLegacy = "application/ssi=agent-wire"
	httpScheme            = "http"
)

type outboundCommHTTPOpts struct {
	client *http.Client
}

type OutboundHTTPOpt func(opts *outboundCommHTTPOpts)

func WithOutboundHTTPClient(client *http.Client) OutboundHTTPOpt {
	return func(opts *outboundCommHTTPOpts) {
		opts.client = client
	}
}

func WithOutboundTimeout(timeout time.Duration) OutboundHTTPOpt {
	return func(opts *outboundCommHTTPOpts) {
		opts.client.Timeout = timeout
	}
}

func WithOutboundTLSConfig(tlsConfig *tls.Config) OutboundHTTPOpt {
	return func(opts *outboundCommHTTPOpts) {
		opts.client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		}
	}
}

type OutboundHTTPClient struct {
	client *http.Client
}

func NewOutbound(opts ...OutboundHTTPOpt) (*OutboundHTTPClient, error) {
	clOpts := &outboundCommHTTPOpts{}
	for _, opt := range opts {
		opt(clOpts)
	}

	if clOpts.client == nil {
		return nil, errors.New("creation of outbound transport requires an HTTP client")
	}

	cs := &OutboundHTTPClient{
		client: clOpts.client,
	}

	return cs, nil
}

func (cs *OutboundHTTPClient) Start(prov transport.Provider) error {
	return nil
}

func (cs *OutboundHTTPClient) Send(data []byte, destination *service.Destination) (string, error) {
	uri, err := destination.ServiceEndpoint.URI()
	if err != nil {
		return "", fmt.Errorf("error getting ServiceEndpoint URI: %w", err)
	}

	resp, err := cs.client.Post(uri, commContentType, bytes.NewBuffer(data))
	if err != nil {
		logger.Errorf("posting DID envelope to agent faild [%s, %v]", destination.ServiceEndpoint, err)
		return "", err
	}

	var respData string
	if resp != nil {
		defer func() {
			e := resp.Body.Close()
			if e != nil {
				logger.Errorf("close response body failed: %v", e)
			}
		}()

		buf := new(bytes.Buffer)

		_, e := buf.ReadFrom(resp.Body)
		if e != nil {
			return "", e
		}

		respData = buf.String()

		isStatusSuccess := resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusOK
		if !isStatusSuccess {
			logger.Errorf("didcomm failed: transport=http serviceEpdoint=%s, status=%v, errMsg=%s",
				destination.ServiceEndpoint, resp.Status, respData)

			return "", fmt.Errorf("received unsuccessful POST HTTP status from agent [%s, %v, %s]",
				destination.ServiceEndpoint, resp.Status, respData)
		}
	}

	return respData, nil
}

func (cs *OutboundHTTPClient) AcceptRecipient([]string) bool {
	return false
}

func (cs *OutboundHTTPClient) Accept(url string) bool {
	return strings.HasPrefix(url, httpScheme)
}

var _ transport.OutboundTransport = (*OutboundHTTPClient)(nil)
