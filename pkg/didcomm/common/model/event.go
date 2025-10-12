package model

type Event interface {
	ConnectionID() string
	InvitationID() string
}
