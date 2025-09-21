package http

import (
	"context"
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/log"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport/internal"
	"github.com/rs/cors"
	"io/ioutil"
	"net/http"
)

var logger = log.New("aries-framework/http")

func NewInboundHandler(prov transport.Provider) (http.Handler, error) {
	if prov == nil || prov.InboundMessageHandler() == nil {
		logger.Errorf("Error creating a new inbound handler: message handler function is nil")
		return nil, errors.New("creation of inbound handler failed")
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		processPOSTRequest(w, r, prov)
	})

	return cors.Default().Handler(handler), nil
}

func processPOSTRequest(w http.ResponseWriter, r *http.Request, prov transport.Provider) {
	if valid := validateHTTPMethod(w, r); !valid {
		return
	}

	if valid := validatePayload(r, w); !valid {
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		logger.Errorf("Error reading request body: %s - returning Code: %d", err, http.StatusInternalServerError)
		http.Error(w, "Failed to read payload", http.StatusInternalServerError)
		return
	}

	unpackMsg, err := internal.UnpackMessage(body, prov.Packager(), "http")
	if err != nil {
		logger.Errorf("%w - returning Code: %d", err, http.StatusInternalServerError)
		http.Error(w, "failed to unpack msg", http.StatusInternalServerError)
		return
	}

	messageHandler := prov.InboundMessageHandler()
	err = messageHandler(unpackMsg)
	if err != nil {
		logger.Errorf("incoming msg processing failed: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		w.WriteHeader(http.StatusAccepted)
	}
}

func validateHTTPMethod(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "HTTP Method not allowed", http.StatusMethodNotAllowed)
		return false
	}

	ct := r.Header.Get("Content-Type")

	if ct != commContentType && ct != commContentTypeLegacy {
		http.Error(w, fmt.Sprintf("Unsupported Content-type '%s'", ct), http.StatusUnsupportedMediaType)
		return false
	}

	return true
}

func validatePayload(r *http.Request, w http.ResponseWriter) bool {
	if r.ContentLength == 0 {
		http.Error(w, "Empty payload", http.StatusBadRequest)
		return false
	}

	return true
}

type Inbound struct {
	externalAddr string
	server       *http.Server
	certFile     string
	keyFile      string
}

func NewInbound(internalAddr, externalAddr, certFile, keyFile string) (*Inbound, error) {
	if internalAddr == "" {
		return nil, errors.New("http address is mandatory")
	}

	if externalAddr == "" {
		externalAddr = internalAddr
	}

	return &Inbound{
		certFile:     certFile,
		keyFile:      keyFile,
		externalAddr: externalAddr,
		server:       &http.Server{Addr: internalAddr},
	}, nil
}

func (i *Inbound) Start(prov transport.Provider) error {
	handler, err := NewInboundHandler(prov)
	if err != nil {
		return fmt.Errorf("HTTP server start failed: %w", err)
	}

	i.server.Handler = handler

	go func() {
		if err := i.listenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("HTTP server start with address[%s] failed, cause: %s", i.server.Addr, err)
		}
	}()

	return nil
}

func (i *Inbound) listenAndServe() error {
	if i.certFile != "" && i.keyFile != "" {
		return i.server.ListenAndServeTLS(i.certFile, i.keyFile)
	}

	return i.server.ListenAndServe()
}

func (i *Inbound) Stop() error {
	if err := i.server.Shutdown(context.Background()); err != nil {
		return fmt.Errorf("HTTP server shutdown failed: %w", err)
	}

	return nil
}

func (i *Inbound) Endpoint() string {
	return i.externalAddr
}
