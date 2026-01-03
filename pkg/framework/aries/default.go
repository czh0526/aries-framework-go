package aries

import (
	"fmt"
	messagepickup "github.com/czh0526/aries-framework-go/pkg/didcomm/protocol/mssagepickup"
	"net/http"

	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms/localkms"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/secretlock/noop"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/packager"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/packer"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/packer/anoncrypt"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/packer/authcrypt"
	legacy_anoncrypt "github.com/czh0526/aries-framework-go/pkg/didcomm/packer/legacy/anoncrypt"
	legacy_authcrypt "github.com/czh0526/aries-framework-go/pkg/didcomm/packer/legacy/authcrypt"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
	aries_http "github.com/czh0526/aries-framework-go/pkg/didcomm/transport/http"
	doc_jose "github.com/czh0526/aries-framework-go/pkg/doc/jose"
	ariesapi "github.com/czh0526/aries-framework-go/pkg/framework/aries/api"
	"github.com/czh0526/aries-framework-go/pkg/framework/context"
	"github.com/czh0526/aries-framework-go/pkg/store/verifiable"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
)

func defFrameworkOpts(aries *Aries) error {

	// 设置 Outbound Transport
	if len(aries.outboundTransports) == 0 {
		outbound, err := aries_http.NewOutbound(
			aries_http.WithOutboundHTTPClient(&http.Client{}))
		if err != nil {
			return fmt.Errorf("http outbound transport initialization failed: %w", err)
		}

		aries.outboundTransports = append(aries.outboundTransports, outbound)
	}

	// 设置 Store Provider
	if aries.storeProvider == nil {
		aries.storeProvider = storeProvider()
	}

	// 创建 JSON-LD ContextStore
	err := createJSONLDContextStore(aries)
	if err != nil {
		return err
	}

	// 创建 remote JSON-LD provider store
	err = createJSONLDRemoteProviderStore(aries)
	if err != nil {
		return err
	}

	// 创建 JSON-LD document loader
	err = createJSONLDDocumentLoader(aries)
	if err != nil {
		return err
	}

	// 创建 verifiable store
	err = assignVerifiableStoreIfNeeded(aries, aries.storeProvider)
	if err != nil {
		return err
	}

	//
	aries.protocolSvcCreators = append(aries.protocolSvcCreators,
		newMessagePickupSvc())

	if aries.secretLock == nil && aries.kmsCreator == nil {
		err = createDefSecretLock(aries)
		if err != nil {
			return err
		}
	}

	return setAdditionalDefaultOpts(aries)
}

func createDefSecretLock(aries *Aries) error {
	aries.secretLock = &noop.NoLock{}
	return nil
}

func setAdditionalDefaultOpts(aries *Aries) error {
	err := setDefaultKMSCryptoOpts(aries)
	if err != nil {
		return err
	}

	if aries.keyType == "" {
		aries.keyType = spikms.ED25519Type
	}

	if aries.keyAgreementType == "" {
		aries.keyAgreementType = spikms.X25519ECDHKWType
	}

	if aries.packerCreator == nil {
		aries.packerCreator = func(p packer.Provider) (packer.Packer, error) {
			return legacy_authcrypt.New(p), nil
		}
		aries.packerCreators = []packer.Creator{
			func(p packer.Provider) (packer.Packer, error) {
				return legacy_authcrypt.New(p), nil
			},
			func(p packer.Provider) (packer.Packer, error) {
				return legacy_anoncrypt.New(p), nil
			},

			func(p packer.Provider) (packer.Packer, error) {
				return authcrypt.New(p, jose.A256CBCHS512)
			},
			func(p packer.Provider) (packer.Packer, error) {
				return anoncrypt.New(p, doc_jose.A256GCM)
			},
		}
	}

	if aries.packagerCreator == nil {
		aries.packagerCreator = func(p packager.Provider) (transport.Packager, error) {
			return packager.New(p)
		}
	}

	if aries.protocolStateStoreProvider == nil {
		aries.protocolStateStoreProvider = storeProvider()
	}

	return nil
}

func setDefaultKMSCryptoOpts(aries *Aries) error {
	if aries.kmsCreator == nil {
		aries.kmsCreator = func(provider spikms.Provider) (spikms.KeyManager, error) {
			return localkms.New(defaultMasterKeyURI, provider)
		}
	}

	if aries.crypto == nil {
		cr, err := tinkcrypto.New()
		if err != nil {
			return fmt.Errorf("failed to initialize default crypto: %w", err)
		}
		aries.crypto = cr
	}

	return nil
}

func assignVerifiableStoreIfNeeded(aries *Aries, storeProvider spistorage.Provider) error {
	if aries.verifiableStore != nil {
		return nil
	}

	provider, err := context.New(
		context.WithStorageProvider(storeProvider),
		context.WithJSONLDDocumentLoader(aries.documentLoader))
	if err != nil {
		return fmt.Errorf("failed to initialize verifiable store: %w", err)
	}

	// 构建一个 verifiable store
	aries.verifiableStore, err = verifiable.New(provider)
	if err != nil {
		return fmt.Errorf("can't initialize verifiable store: %w", err)
	}

	return nil
}

func newMessagePickupSvc() ariesapi.ProtocolSvcCreator {
	return ariesapi.ProtocolSvcCreator{
		Create: func(prv ariesapi.Provider) (dispatcher.ProtocolService, error) {
			return &messagepickup.Service{}, nil
		},
	}
}
