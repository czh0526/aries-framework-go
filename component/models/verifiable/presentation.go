package verifiable

type Presentation struct {
	Context       []string
	CustomContext []interface{}
	ID            string
	Type          []string
	credentials   []interface{}
	Holder        string
	Proofs        []Proof
	JWT           string
	CustomFields  CustomFields
}
