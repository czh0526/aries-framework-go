package service

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestAction_MsgEvents(t *testing.T) {
	m := Message{}
	require.Nil(t, m.MsgEvents())
}

func TestAction_RegisterMsgEvents(t *testing.T) {
	m := Message{}

}
