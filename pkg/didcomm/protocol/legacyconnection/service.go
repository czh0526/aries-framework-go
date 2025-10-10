package legacyconnection

const (
	LegacyConnection       = "legacyconnection"
	PIURI                  = "https://didcomm.org/connections/1.0"
	InvitationMsgType      = PIURI + "invitation"
	RequestMsgType         = PIURI + "request"
	ResponseMsgType        = PIURI + "response"
	AckMsgType             = "https://didcomm.org/noticication/1.0/ack"
	routerConnsMetadataKey = "routerConnctions"
)

const (
	myNSPrefix    = "my"
	theirNSPrefix = "their"

	InvitationRecipientKey = "invRecipientKey"
)

type Service struct {
}
