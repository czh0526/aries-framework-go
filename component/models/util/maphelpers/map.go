package maphelpers

func CopyMap(m map[string]interface{}) map[string]interface{} {
	cm := make(map[string]interface{})

	for k, v := range m {
		vm, ok := v.(map[string]interface{})
		if ok {
			cm[k] = CopyMap(vm)
		} else {
			cm[k] = v
		}
	}

	return cm
}
