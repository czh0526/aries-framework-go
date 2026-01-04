package aries

import (
	"fmt"
	messagepickup "github.com/czh0526/aries-framework-go/pkg/didcomm/protocol/mssagepickup"
	"net/http"

	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms/localkms"
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

// defFrameworkOpts 对于外部没有设置的 Aries 属性进行设置
// 包括：
//
//	1）outbound Transports
//	2）store Provider
//	3) JSON-LD Context Store         => 数据库名: ldcontext
//	4) JSON-LD Remote Provider Store => 数据库名: remove_providers
//	5) verifiable Store 			 => 数据库名: verifiable
//	6）JSON-LD Document Loader
//	7) 各种 ServiceCreator 函数集合
//	8) 其它的属性设置
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

	// 设置各种 Service Creator 函数集合
	aries.protocolSvcCreators = append(aries.protocolSvcCreators,
		newMessagePickupSvc())

	if aries.secretLock == nil && aries.kmsCreator == nil {
		err = createDefSecretLock(aries)
		if err != nil {
			return err
		}
	}

	// 设置其他选项
	return setAdditionalDefaultOpts(aries)
}

// setAdditionalDefaultOpts 设置其他选项
// 包括：
//
//	1）KMS + Crypto
//	2）Key Type
//	3）Key Agreement Type
//	4）Packer Creator
//	5）Packager Creator
//	6）Protocol State Store Provider
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
