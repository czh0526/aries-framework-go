package kms

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	"github.com/czh0526/aries-framework-go/component/log"
	"github.com/czh0526/aries-framework-go/pkg/controller/command"
	"github.com/czh0526/aries-framework-go/pkg/internal/logutil"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"io"
)

var logger = log.New("aries-framework/command/kms")

const (
	CommandName = "kms"

	CreateKeySetCommandMethod = "CreateKeySet"
	ImportKeyCommandMethod    = "ImportKey"

	errEmptyKeyType = "key type is mandatory"
	errEmptyKeyID   = "key id is mandatory"
)

const (
	InvalidRequestErrorCode = command.Code(iota + command.KMS)
	CreateKeySetError
	ImportKeyError
)

type provider interface {
	KMS() spikms.KeyManager
}

type Command struct {
	ctx       provider
	importKey func(privKey interface{}, kt spikms.KeyType, opts ...spikms.PrivateKeyOpts) (string, interface{}, error)
}

func (c *Command) CreatKeySet(rw io.Writer, req io.Reader) command.Error {
	var request CreateKeySetRequest

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogError(logger, CommandName, CreateKeySetCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("failed request decode: %w", err))
	}

	if request.KeyType == "" {
		logutil.LogError(logger, CommandName, CreateKeySetCommandMethod, errEmptyKeyType)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyKeyType))
	}

	keyID, pubKeyBytes, err := c.ctx.KMS().CreateAndExportPubKeyBytes(spikms.KeyType(request.KeyType))
	if err != nil {
		logutil.LogError(logger, CommandName, CreateKeySetCommandMethod, err.Error())
		return command.NewExecuteError(CreateKeySetError, err)
	}

	command.WriteNillableResponse(rw, CreateKeySetResponse{
		KeyID:     keyID,
		PublicKey: base64.RawURLEncoding.EncodeToString(pubKeyBytes),
	}, logger)

	logutil.LogDebug(logger, CommandName, CreateKeySetCommandMethod, "success")
	return nil
}

func (c *Command) ImportKey(rw io.Writer, req io.Reader) command.Error {
	buf := new(bytes.Buffer)

	_, err := buf.ReadFrom(req)
	if err != nil {
		logutil.LogError(logger, CommandName, ImportKeyCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("failed request decode: %w", err))
	}

	var j jwk.JWK
	if errUnmarshal := json.Unmarshal(buf.Bytes(), &j); errUnmarshal != nil {
		logutil.LogError(logger, CommandName, ImportKeyCommandMethod, errUnmarshal.Error())
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("failed request decode: %w", err))
	}

	if j.KeyID == "" {
		logutil.LogDebug(logger, CommandName, ImportKeyCommandMethod, errEmptyKeyID)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyKeyID))
	}

	var keyType spikms.KeyType
	switch j.Crv {
	case "Ed25519":
		keyType = spikms.ED25519
	case "P-256":
		if j.Use == "enc" {
			keyType = spikms.NISTP256ECDHKWType
		} else {
			keyType = spikms.ECDSAP256TypeIEEEP1363
		}
	case "BLS12301_G2":
		keyType = spikms.BLS12381G2Type
	default:
		return command.NewValidationError(InvalidRequestErrorCode,
			fmt.Errorf("import key type not supported: %s", j.Crv))
	}

	_, _, err = c.importKey(j.Key, keyType, spikms.WithKeyID(j.KeyID))
	if err != nil {
		logutil.LogError(logger, CommandName, ImportKeyCommandMethod, err.Error())
		return command.NewExecuteError(ImportKeyError, err)
	}

	command.WriteNillableResponse(rw, nil, logger)

	logutil.LogDebug(logger, CommandName, ImportKeyCommandMethod, "success")
	return nil
}

func New(ctx provider) *Command {
	return &Command{
		ctx: ctx,
		importKey: func(privKey interface{}, kt spikms.KeyType,
			opts ...spikms.PrivateKeyOpts) (string, interface{}, error) {
			return ctx.KMS().ImportPrivateKey(privKey, kt, opts...)
		},
	}
}
