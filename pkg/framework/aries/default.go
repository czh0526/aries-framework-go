package aries

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms/localkms"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/packager"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/packer"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/packer/anoncrypt"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
	doc_jose "github.com/czh0526/aries-framework-go/pkg/doc/jose"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
)

func defFrameworkOpts(aries *Aries) error {
	if aries.storeProvider == nil {
		aries.storeProvider = storeProvider()
	}

	// 在 storage 中创建 `context_store`
	err := createJSONLDContextStore(aries)
	if err != nil {
		return err
	}

	// 在 storage 中创建 `remote_provider_store`
	err = createJSONLDRemoteProviderStore(aries)
	if err != nil {
		return err
	}

	// 根据 context_store, remote_provider_store,
	// 创建 `document_loader`
	err = createJSONLDDocumentLoader(aries)
	if err != nil {
		return err
	}

	return setAdditionalDefaultOpts(aries)
}

func setAdditionalDefaultOpts(aries *Aries) error {
	err := setDefaultKMSCryptoOpts(aries)
	if err != nil {
		return err
	}

	if aries.packerCreator == nil {
		aries.packerCreator = func(p packer.Provider) (packer.Packer, error) {
			return anoncrypt.New(p, doc_jose.A256GCM)
		}

		aries.packerCreators = []packer.Creator{
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
