package vdr

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestRegistry_New(t *testing.T) {
	t.Run("test new success", func(t *testing.T) {
		registry := New()
		require.NotNil(t, registry)
	})

	t.Run("test new with opts success", func(t *testing.T) {
		const sampleSvcType = "sample-svc-type"
		const sampleSvcEndpoint = "sample-svc-endpoint"
		registry := New(
			WithDefaultServiceEndpoint(sampleSvcEndpoint),
			WithDefaultServiceType(sampleSvcType))
		require.NotNil(t, registry)
		require.Equal(t, sampleSvcEndpoint, registry.defServiceEndpoint)
		require.Equal(t, sampleSvcType, registry.defServiceType)
	})
}
