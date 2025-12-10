package verifiable

import (
	_ "embed"
	ldcontext "github.com/czh0526/aries-framework-go/component/models/ld/context"
	lddocloader "github.com/czh0526/aries-framework-go/component/models/ld/documentloader"
	ldtestutil "github.com/czh0526/aries-framework-go/component/models/ld/testutil"
	"github.com/stretchr/testify/require"
	"testing"
)

//go:embed testdata/valid_credential.jsonld
var validCredential string

func parseTestCredential(t *testing.T, vcData []byte, opts ...CredentialOpt) (*Credential, error) {
	t.Helper()

	return ParseCredential(vcData,
		append([]CredentialOpt{
			WithJSONLDDocumentLoader(createTestDocumentLoader(t)),
		}, opts...)...)
}

func createTestDocumentLoader(t *testing.T, extraContexts ...ldcontext.Document) *lddocloader.DocumentLoader {
	t.Helper()

	loader, err := ldtestutil.DocumentLoader(extraContexts...)
	require.NoError(t, err)

	return loader
}

func TestCredential_MarshalJSON(t *testing.T) {
	t.Run("round trip conversion of credential with plain issuer", func(t *testing.T) {
		vc, err := parseTestCredential(t, []byte(validCredential))
		require.NoError(t, err)
		require.NotEmpty(t, vc)
	})
}
