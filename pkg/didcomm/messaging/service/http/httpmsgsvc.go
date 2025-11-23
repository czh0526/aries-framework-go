package http

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/log"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"
	"net/http"
)

const (
	OverDIDCommSpec = "https:/didcomm.org/http-over-didcomm/1.0/"

	OverDIDCommMsgRequestType = OverDIDCommSpec + "request"

	errNameAndHandleMandatory   = "service name and http request handle is mandatory"
	errFailedToDecodeMsg        = "unable to decode DID comm message: %w"
	errFailedToDecodeBody       = "unable to decode message body: %w"
	errFailedToCreateNewRequest = "failed to create http request from incoming message: %w"

	httpMessage = "httpMessage"
)

var logger = log.New("aries-framework/httpmsg")

type RequestHandle func(msgID string, request *http.Request) error

type OverDIDComm struct {
	name       string
	purpose    []string
	httpHandle RequestHandle
}

func (m *OverDIDComm) Name() string {
	return m.name
}

func (m *OverDIDComm) Accept(msgType string, purpose []string) bool {
	if msgType != OverDIDCommMsgRequestType {
		return false
	}

	if len(purpose) == 0 {
		return true
	}

	for _, msgPurpose := range purpose {
		for _, svcPurpose := range m.purpose {
			if msgPurpose == svcPurpose {
				return true
			}
		}
	}

	return false
}

func (m *OverDIDComm) HandleInbound(msg service.DIDCommMsg, _ service.DIDCommContext) (string, error) {
	svcMsg := httpOverDIDCommMsg{}

	err := msg.Decode(&svcMsg)
	if err != nil {
		return "", fmt.Errorf(errFailedToDecodeMsg, err)
	}

	rqBody, err := base64.StdEncoding.DecodeString(svcMsg.BodyB64)
	if err != nil {
		return "", fmt.Errorf(errFailedToDecodeBody, err)
	}

	request, err := http.NewRequest(svcMsg.Method, svcMsg.ResourceURI, bytes.NewBuffer(rqBody))
	if err != nil {
		return "", fmt.Errorf(errFailedToCreateNewRequest, err)
	}

	for _, header := range svcMsg.Headers {
		request.Header.Add(header.Name, header.Value)
	}

	return "", m.httpHandle(msg.ID(), request)
}
