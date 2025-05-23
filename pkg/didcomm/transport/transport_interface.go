package transport

type Envelope struct {
	MediaTypeProfile string
	Message          []byte
	FromKey          []byte
	ToKeys           []string
	ToKey            []byte
}

type Packager interface {
	PackMessage(envelope *Envelope) ([]byte, error)

	UnpackMessage(encMessage []byte) (*Envelope, error)
}
