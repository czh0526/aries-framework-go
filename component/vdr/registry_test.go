package vdr

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/component/models/did"
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	mockvdr "github.com/czh0526/aries-framework-go/component/vdr/mock"
	spivdr "github.com/czh0526/aries-framework-go/spi/vdr"
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

func TestRegistry_Resolve(t *testing.T) {
	t.Run("test invalid did input", func(t *testing.T) {
		registry := New()
		d, err := registry.Resolve("id")
		require.Error(t, err)
		require.Contains(t, err.Error(), "wrong format did input")
		require.Nil(t, d)
	})

	t.Run("test did method not supported", func(t *testing.T) {
		registry := New(WithVDR(&mockvdr.VDR{AcceptValue: false}))
		d, err := registry.Resolve("1:id:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "did method id not supported for vdr")
		require.Nil(t, d)
	})

	t.Run("test DID not found", func(t *testing.T) {
		registry := New(WithVDR(&mockvdr.VDR{
			AcceptValue: true,
			ReadFunc: func(didID string, opts ...spivdr.DIDMethodOption) (*did.DocResolution, error) {
				return nil, vdrapi.ErrNotFound
			},
		}))
		d, err := registry.Resolve("1:id:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), vdrapi.ErrNotFound.Error())
		require.Nil(t, d)
	})

	t.Run("test error from resolve did", func(t *testing.T) {
		registry := New(WithVDR(&mockvdr.VDR{
			AcceptValue: true,
			ReadFunc: func(didID string, opts ...spivdr.DIDMethodOption) (*did.DocResolution, error) {
				return nil, fmt.Errorf("read error")
			},
		}))
		d, err := registry.Resolve("1:id:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "read error")
		require.Nil(t, d)
	})

	t.Run("test opts passed", func(t *testing.T) {
		registry := New(WithVDR(&mockvdr.VDR{
			AcceptValue: true,
			ReadFunc: func(didID string, opts ...spivdr.DIDMethodOption) (*did.DocResolution, error) {
				didOpts := &spivdr.DIDMethodOpts{
					Values: make(map[string]interface{}),
				}

				for _, opt := range opts {
					opt(didOpts)
				}

				require.NotNil(t, didOpts.Values["k1"])
				return nil, nil
			},
		}))
		_, err := registry.Resolve("1:id:123", spivdr.WithOption("k1", "v1"))
		require.NoError(t, err)
	})

	t.Run("test opts passed to accept", func(t *testing.T) {
		registry := New(WithVDR(&mockvdr.VDR{
			AcceptFunc: func(method string, opts ...spivdr.DIDMethodOption) bool {
				acceptOpts := &spivdr.DIDMethodOpts{
					Values: make(map[string]interface{}),
				}

				for _, opt := range opts {
					opt(acceptOpts)
				}

				require.NotNil(t, acceptOpts.Values["k1"])
				require.NotNil(t, acceptOpts.Values[didAcceptOpt])
				return true
			},
		}))
		_, err := registry.Resolve("1:id:123", spivdr.WithOption("k1", "v1"))
		require.NoError(t, err)
	})

	t.Run("test success", func(t *testing.T) {
		registry := New(WithVDR(&mockvdr.VDR{
			AcceptValue: true,
		}))
		_, err := registry.Resolve("1:id:123")
		require.NoError(t, err)
	})
}

func TestRegistry_Update(t *testing.T) {
	t.Run("test invalid did input", func(t *testing.T) {
		registry := New()
		err := registry.Update(&did.Doc{ID: "id"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "wrong format did input")
	})

	t.Run("test did method not supported", func(t *testing.T) {
		registry := New(WithVDR(&mockvdr.VDR{
			AcceptValue: false,
		}))
		err := registry.Update(&did.Doc{ID: "1:id:123"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "did method id not supported for vdr")
	})

	t.Run("test error from update did", func(t *testing.T) {
		registry := New(WithVDR(&mockvdr.VDR{
			AcceptValue: true,
			UpdateFunc: func(did *did.Doc, opts ...spivdr.DIDMethodOption) error {
				return fmt.Errorf("update error")
			},
		}))
		err := registry.Update(&did.Doc{ID: "1:id:123"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "update error")
	})

	t.Run("test opts passwd", func(t *testing.T) {
		registry := New(WithVDR(&mockvdr.VDR{
			AcceptValue: true,
			UpdateFunc: func(did *did.Doc, opts ...spivdr.DIDMethodOption) error {
				didOpts := &spivdr.DIDMethodOpts{
					Values: make(map[string]interface{}),
				}

				for _, opt := range opts {
					opt(didOpts)
				}

				require.NotNil(t, didOpts.Values["k1"])
				return nil
			},
		}))
		err := registry.Update(&did.Doc{ID: "1:id:123"}, spivdr.WithOption("k1", "v1"))
		require.NoError(t, err)
	})

	t.Run("test opts passed to accept", func(t *testing.T) {
		registry := New(WithVDR(&mockvdr.VDR{
			AcceptFunc: func(method string, opts ...spivdr.DIDMethodOption) bool {
				acceptOpts := &spivdr.DIDMethodOpts{
					Values: make(map[string]interface{}),
				}

				for _, opt := range opts {
					opt(acceptOpts)
				}

				require.NotNil(t, acceptOpts.Values["k1"])
				require.NotNil(t, acceptOpts.Values[didAcceptOpt])
				return true
			},
		}))
		err := registry.Update(&did.Doc{ID: "1:id:123"}, spivdr.WithOption("k1", "v1"))
		require.NoError(t, err)
	})

	t.Run("test success", func(t *testing.T) {
		registry := New(WithVDR(&mockvdr.VDR{
			AcceptValue: true,
		}))
		err := registry.Update(&did.Doc{ID: "1:id:123"})
		require.NoError(t, err)
	})
}

func TestRegistry_Create(t *testing.T) {
	t.Run("test did method not supported", func(t *testing.T) {
		registry := New(WithVDR(&mockvdr.VDR{AcceptValue: false}))
		d, err := registry.Create("id", &did.Doc{ID: "did"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "did method id not supported for vdr")
		require.Nil(t, d)
	})
}
