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
	// 构建行为监听器
	a := Action{}

	// 测试注册空的监听通道，失败
	err := a.RegisterActionEvent(nil)
	require.EqualError(t, err, ErrNilChannel.Error())

	// 测试第一次注册监听通道，成功
	ch := make(chan DIDCommAction)
	err = a.RegisterActionEvent(ch)
	require.Nil(t, err)
	require.EqualValues(t, ch, a.ActionEvent())

	// 测试第二次注册监听通道，失败
	newCh := make(chan DIDCommAction)
	err = a.RegisterActionEvent(newCh)
	require.EqualError(t, err, ErrChannelRegistered.Error())
}

func TestAction_UnregisterActionEvent(t *testing.T) {
	a := Action{}

	err := a.UnregisterActionEvent(nil)
	require.EqualError(t, err, ErrNilChannel.Error())

	ch := make(chan DIDCommAction)
	err = a.UnregisterActionEvent(ch)
	require.EqualError(t, err, ErrInvalidChannel.Error())

	err = a.RegisterActionEvent(ch)
	require.Nil(t, err)
	err = a.UnregisterActionEvent(ch)
	require.Nil(t, err)
}
