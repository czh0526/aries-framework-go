package service

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestNewDIDCommContext(t *testing.T) {
	t.Run("returns DIDs and properties", func(t *testing.T) {
		myDID := uuid.New().String()
		theirDID := uuid.New().String()
		propKey := uuid.New().String()
		propValue := uuid.New().String()

		c := NewDIDCommContext(myDID, theirDID, map[string]interface{}{
			propKey: propValue,
		})
		require.NotNil(t, c)

		require.Equal(t, myDID, c.MyDID())
		require.Equal(t, theirDID, c.TheirDID())
		p, ok := c.All()[propKey].(string)
		require.True(t, ok)
		require.Equal(t, propValue, p)
	})

}

func TestEmptyDIDCommContext(t *testing.T) {
	t.Run("returns an empty context", func(t *testing.T) {
		c := EmptyDIDCommContext()
		require.NotNil(t, c)
		require.Empty(t, c.MyDID())
		require.Empty(t, c.TheirDID())
		require.Empty(t, c.All())
	})
}
