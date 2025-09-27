package did

func LookupPublicKey(id string, didDoc *Doc) (*VerificationMethod, bool) {
	for _, key := range didDoc.VerificationMethod {
		if key.ID == id {
			return &key, true
		}
	}
	return nil, false
}
