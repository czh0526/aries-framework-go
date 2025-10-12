package didexchange

type OOBInvitation struct {
	ID                string `json:"@id"`
	Type              string `json:"@type"`
	ThreadID          string
	TheirLabel        string
	MyLabel           string
	Target            interface{}
	MediaTypeProfiles []string
}
