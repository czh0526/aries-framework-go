package service

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestAction_ActionEvent(t *testing.T) {
	a := Action{}
	require.Nil(t, a.ActionEvent())
}

func TestAction_RegisterActionEvent(t *testing.T) {
	a := Action{}

	err := a.RegisterActionEvent(nil)
	require.EqualError(t, err, ErrNilChannel.Error())

	ch := make(chan DIDCommAction)
	err = a.RegisterActionEvent(ch)
	require.Nil(t, err)
	require.EqualValues(t, ch, a.ActionEvent())

	newCh := make(chan DIDCommAction)
	err = a.RegisterActionEvent(newCh)
	require.EqualError(t, err, ErrChannelRegistered.Error())
}
