package aries

import (
	mockkms "github.com/czh0526/aries-framework-go/component/kmscrypto/mock/kms"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestFramework(t *testing.T) {
	t.Run("test Aries framework - with no options", func(t *testing.T) {
		_, err := New()
		require.NoError(t, err)
	})

	t.Run("test KMS svc - with user provided instance", func(t *testing.T) {
		_, err := New(WithKMS(func(provider spikms.Provider) (spikms.KeyManager, error) {
			return mockkms.KeyManager{CreateKeyID: "abc"}, nil
		}))
		require.NoError(t, err)
	})
}
