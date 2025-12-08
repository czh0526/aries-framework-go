package testutil

import (
	_ "embed"
	ldcontext "github.com/czh0526/aries-framework-go/component/models/ld/context"
	"github.com/czh0526/aries-framework-go/component/models/ld/documentloader"
	mockldstore "github.com/czh0526/aries-framework-go/component/models/ld/mock"
	ldstore "github.com/czh0526/aries-framework-go/component/models/ld/store"
)

var (
	//go:embed contexts/third_party/w3c-ccg.github.io/citizenship_v1.jsonld
	citizenship []byte
	//go:embed contexts/third_party/w3c-ccg.github.io/revocation-list-2021.jsonld
	revocationList2021 []byte
	//go:embed contexts/third_party/w3.org/odrl.jsonld
	odrl []byte
	//go:embed contexts/third_party/w3.org/credentials-examples_v1.jsonld
	credentialExamples []byte
	//go:embed contexts/third_party/trustbloc.github.io/trustbloc-examples_v1.jsonld
	vcExamples []byte
	//go:embed contexts/third_party/trustbloc.github.io/trustbloc-authorization-credential_v1.jsonld
	authCred []byte
	//go:embed contexts/third_party/w3id.org/data-integrity-v1.jsonld
	dataIntegrity []byte
)

var testContexts = []ldcontext.Document{
	{
		URL:         "https://w3id.org/citizenship/v1",
		DocumentURL: "https://w3c-ccg.github.io/citizenship-vocab/contexts/citizenship-v1.jsonld",
		Content:     citizenship,
	},
	{
		URL:     "https://www.w3.org/ns/odrl.jsonld",
		Content: odrl,
	},
	{
		URL:     "https://www.w3.org/2018/credentials/examples/v1",
		Content: credentialExamples,
	},
	{
		URL:     "https://trustbloc.github.io/context/vc/examples-v1.jsonld",
		Content: vcExamples,
	},
	{
		URL:     "https://trustbloc.github.io/context/vc/authorization-credential-v1.jsonld",
		Content: authCred,
	},
	{
		URL:         "https://w3c-ccg.github.io/vc-revocation-list-2021/contexts/v1.jsonld",
		DocumentURL: "https://raw.githubusercontent.com/w3c-ccg/vc-status-list-2021/343b8b59cddba4525e1ef355356ae760fc75904e/contexts/v1.jsonld", //nolint:lll
		Content:     revocationList2021,
	},
	{
		URL:     "https://w3id.org/security/data-integrity/v1",
		Content: dataIntegrity,
	},
}

func DocumentLoader(extraContexts ...ldcontext.Document) (*documentloader.DocumentLoader, error) {
	return createTestDocumentLoader(extraContexts...)
}

type mockProvider struct {
	ContextStore        ldstore.ContextStore
	RemoteProviderStore ldstore.RemoteProviderStore
}

func createTestDocumentLoader(extraContexts ...ldcontext.Document) (*documentloader.DocumentLoader, error) {
	contexts := append(testContexts, extraContexts...)

	p := &mockProvider{
		ContextStore: mockldstore.NewMockContextStore(),
	}
}
