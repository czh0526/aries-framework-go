package didexchange

type didExchangeEvent struct {
	connectionID string
	invitationID string
}

func (ex *didExchangeEvent) ConnectionID() string {
	return ex.connectionID
}

func (ex *didExchangeEvent) InvitationID() string {
	return ex.invitationID
}

func (ex *didExchangeEvent) All() map[string]interface{} {
	return map[string]interface{}{
		"connectionID": ex.connectionID,
		"invitationID": ex.invitationID,
	}
}

type didExchangeEventError struct {
	didExchangeEvent
	err error
}
