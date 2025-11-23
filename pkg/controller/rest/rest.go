package rest

import (
	"encoding/json"
	"github.com/czh0526/aries-framework-go/component/log"
	"github.com/czh0526/aries-framework-go/pkg/controller/command"
	"io"
	"net/http"
)

var logger = log.New("aries-framework/rest")

type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

func Execute(exec command.Exec, rw http.ResponseWriter, req io.Reader) {
	rw.Header().Set("Content-Type", "application/json")

	err := exec(rw, req)
	if err != nil {
		SendError(rw, err)
	}
}

func SendError(rw http.ResponseWriter, err command.Error) {
	var status int

	switch err.Type() {
	case command.ValidationError:
		status = http.StatusBadRequest
	default:
		status = http.StatusInternalServerError
	}

	SendHTTPStatusError(rw, status, err.Code(), err)
}

type genericErrorBody struct {
	Code    command.Code `json:"code"`
	Message string       `json:"message"`
}

func SendHTTPStatusError(rw http.ResponseWriter, httpStatus int, code command.Code, err command.Error) {
	rw.WriteHeader(httpStatus)

	e := json.NewEncoder(rw).Encode(&genericErrorBody{
		Code:    code,
		Message: err.Error(),
	})
	if e != nil {
		logger.Errorf("failed to encode error response: %s", e)
	}
}
