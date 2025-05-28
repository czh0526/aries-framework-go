package aries

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/component/models/ld/documentloader"
	ldstore "github.com/czh0526/aries-framework-go/component/models/ld/store"
	"github.com/czh0526/aries-framework-go/component/vdr"
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	"github.com/czh0526/aries-framework-go/component/vdr/key"
	"github.com/czh0526/aries-framework-go/component/vdr/peer"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/packager"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/packer"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
	"github.com/czh0526/aries-framework-go/pkg/framework/context"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
	"github.com/google/uuid"
	jsonld "github.com/piprate/json-gold/ld"
)

const (
	defaultEndpoint     = "didcomm:transport/queue"
	defaultMasterKeyURI = "local-lock://default/master/key/"
)

type Aries struct {
	id                  string
	kms                 spikms.KeyManager
	kmsCreator          spikms.Creator
	crypto              spicrypto.Crypto
	vdr                 []vdrapi.VDR
	vdrRegistry         vdrapi.Registry
	storeProvider       spistorage.Provider
	contextStore        ldstore.ContextStore
	remoteProviderStore ldstore.RemoteProviderStore
	documentLoader      jsonld.DocumentLoader
	packerCreator       packer.Creator
	packerCreators      []packer.Creator
	packagerCreator     packager.Creator
	mediaTypeProfiles   []string
}

type Option func(opts *Aries) error

func New(opts ...Option) (*Aries, error) {
	aries := &Aries{}

	// 设置 aries 对象的属性
	for _, option := range opts {
		err := option(aries)
		if err != nil {
			return nil, fmt.Errorf("option initialization failed: %v", err)
		}
	}

	// 设置 id
	aries.id = uuid.New().String()

	// 设置 store provider
	err := defFrameworkOpts(aries)
	if err != nil {
		return nil, fmt.Errorf("default option initialization failed: %v", err)
	}

	return initializeServices(aries)
}

func initializeServices(aries *Aries) (*Aries, error) {
	if err := createKMS(aries); err != nil {
		return nil, err
	}

	if err := createVDR(aries); err != nil {
		return nil, err
	}

	if err := createPackersAndPackager(aries); err != nil {
		return nil, err
	}

	//if err := loadServices(aries); err != nil {
	//	return nil, err
	//}

	return aries, nil
}

type kmsProvider struct{}

func WithKMS(creator spikms.Creator) Option {
	return func(aries *Aries) error {
		aries.kmsCreator = creator
		return nil
	}
}

func WithCrypto(c spicrypto.Crypto) Option {
	return func(aries *Aries) error {
		aries.crypto = c
		return nil
	}
}

func WithVDR(v vdrapi.VDR) Option {
	return func(aries *Aries) error {
		aries.vdr = append(aries.vdr, v)
		return nil
	}
}

func createKMS(aries *Aries) error {
	var err error

	kmsProv := &kmsProvider{}

	aries.kms, err = aries.kmsCreator(kmsProv)
	if err != nil {
		return fmt.Errorf("create KMS failed: %v", err)
	}

	return nil
}

func createVDR(aries *Aries) error {
	ctx, err := context.New(
		context.WithKMS(aries.kms),
		context.WithCrypto(aries.crypto),
		context.WithStorageProvider(aries.storeProvider),
		context.WithServiceEndpoint(serviceEndpoint(aries)),
	)
	if err != nil {
		return fmt.Errorf("create context failed: %v", err)
	}

	var vdrOpts []vdr.Option
	for _, v := range aries.vdr {
		vdrOpts = append(vdrOpts, vdr.WithVDR(v))
	}

	// 将 did:peer:xxxxx 注册进 VDRegistry
	p, err := peer.New(ctx.StorageProvider())
	if err != nil {
		return fmt.Errorf("create new vdr peer failed: %v", err)
	}

	dst := vdrapi.DIDCommServiceType
	for _, mediaType := range aries.mediaTypeProfiles {
		if mediaType == transport.MediaTypeDIDCommV2Profile ||
			mediaType == transport.MediaTypeAIP2RFC0587Profile {
			dst = vdrapi.DIDCommV2ServiceType
			break
		}
	}

	vdrOpts = append(vdrOpts,
		vdr.WithVDR(p),
		vdr.WithDefaultServiceType(dst),
		vdr.WithDefaultServiceEndpoint(serviceEndpoint(aries)),
	)

	// 将 did:key:xxxxx 注册进 VDRegistry
	k := key.New()
	vdrOpts = append(vdrOpts, vdr.WithVDR(k))
	aries.vdrRegistry = vdr.New(vdrOpts...)

	return nil
}

func createJSONLDContextStore(aries *Aries) error {
	if aries.contextStore != nil {
		return nil
	}

	s, err := ldstore.NewContextStore(aries.storeProvider)
	if err != nil {
		return fmt.Errorf("init JSON-LD remote context store failed, err = %v", err)
	}

	aries.contextStore = s
	return nil
}

func createJSONLDRemoteProviderStore(aries *Aries) error {
	if aries.remoteProviderStore != nil {
		return nil
	}

	s, err := ldstore.NewRemoteProviderStore(aries.storeProvider)
	if err != nil {
		return fmt.Errorf("init JSON-LD remote provider store failed, err = %v", err)
	}

	aries.remoteProviderStore = s
	return nil
}

func createJSONLDDocumentLoader(aries *Aries) error {
	if aries.documentLoader != nil {
		return nil
	}

	ctx, err := context.New(
		context.WithJSONLDContextStore(aries.contextStore),
		context.WithJSONLDRemoteProviderStore(aries.remoteProviderStore),
	)
	if err != nil {
		return fmt.Errorf("init JSON-LD document loader failed, err = %v", err)
	}

	documentLoader, err := documentloader.NewDocumentLoader(ctx)
	if err != nil {
		return fmt.Errorf("init JSON-LD document loader failed, err = %v", err)
	}

	aries.documentLoader = documentLoader
	return nil
}

func serviceEndpoint(aries *Aries) string {
	return fetchEndpoint(aries, "ws")
}

func fetchEndpoint(aries *Aries, defaultScheme string) string {
	return defaultEndpoint
}

func createPackersAndPackager(aries *Aries) error {
	return nil
}
