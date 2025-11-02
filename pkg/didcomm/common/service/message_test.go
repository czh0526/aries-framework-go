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

	err := m.RegisterMsgEvent(nil)
	require.EqualError(t, err, ErrNilChannel.Error())

	ch := make(chan<- StateMsg)
	err = m.RegisterMsgEvent(ch)
	require.Nil(t, err)
	require.Equal(t, 1, len(m.MsgEvents()))

	err = m.RegisterMsgEvent(ch)
	require.Nil(t, err)
	require.Equal(t, 2, len(m.MsgEvents()))
}

func TestAction_UnregisterMsgEvent(t *testing.T) {
	m := Message{}

	ch := make(chan<- StateMsg)
	err := m.RegisterMsgEvent(ch)
	require.Nil(t, err)
	require.Equal(t, 1, len(m.MsgEvents()))

	err = m.UnregisterMsgEvent(ch)
	require.Nil(t, err)
	require.Equal(t, 0, len(m.MsgEvents()))

	err = m.RegisterMsgEvent(ch)
	require.Nil(t, err)
	err = m.RegisterMsgEvent(ch)
	require.Nil(t, err)
	require.Equal(t, 2, len(m.MsgEvents()))

	err = m.UnregisterMsgEvent(ch)
	require.Nil(t, err)
	require.Equal(t, 0, len(m.MsgEvents()))

	err = m.UnregisterMsgEvent(ch)
	require.Nil(t, err)
}
