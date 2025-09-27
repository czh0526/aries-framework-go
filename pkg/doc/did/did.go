package did

import didmodel "github.com/czh0526/aries-framework-go/component/models/did"

func LookupPublicKey(id string, didDoc *didmodel.Doc) (*didmodel.VerificationMethod, bool) {
	return didmodel.LookupPublicKey(id, didDoc)
}
