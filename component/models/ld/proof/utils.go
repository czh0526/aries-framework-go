package proof

const (
	jsonldProof = "proof"
)

// AddProof adds a proof to a JSON-LD object
func AddProof(jsonLdObject map[string]interface{}, proof *Proof) error {
	var proofs []interface{}

	entry, exists := jsonLdObject[jsonldProof]
	if exists {
		// 兼容 Proof 为一个或者多个的场景
		switch p := entry.(type) {
		case []interface{}:
			proofs = p
		case map[string]interface{}:
			proofs = []interface{}{p}

		}
	}

	proofs = append(proofs, proof)
	jsonLdObject[jsonldProof] = proofs

	return nil
}

func GetCopyWithoutProof(jsonLdObject map[string]interface{}) map[string]interface{} {
	if jsonLdObject == nil {
		return nil
	}

	dest := make(map[string]interface{})

	for k, v := range jsonLdObject {
		if k != jsonldProof {
			dest[k] = v
		}
	}
	return dest
}
