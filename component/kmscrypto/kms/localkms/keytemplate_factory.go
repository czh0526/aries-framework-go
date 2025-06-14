package localkms

import (
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func getKeyTemplate(keyType spikms.KeyType, opts ...spikms.KeyOpts) (*tinkpb.KeyTemplate, error) {
	return keyTemplate(keyType, opts...)
}
