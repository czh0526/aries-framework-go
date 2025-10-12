package service

import (
	"fmt"
	"testing"
)

func TestAutoExecuteActionEvent(t *testing.T) {
	ch := make(chan DIDCommAction)
	done := make(chan struct{})

	go func() {
		AutoExecuteActionEvent(ch)
		close(done)
	}()

	ch <- DIDCommAction{
		Continue: func(args interface{}) {
			fmt.Println("msg.Continue() executed 1.")
		},
	}

	ch <- DIDCommAction{Continue: func(args interface{}) {
		fmt.Println("msg.Continue() executed 2.")
	}}

	close(ch)
	<-done
}
