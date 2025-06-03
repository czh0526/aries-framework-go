package service

type Version string

type options struct {
	V Version
}

type Opt func(o *options)

type DIDCommMsgMap map[string]interface{}
