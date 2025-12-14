package json

import (
	"encoding/json"
	"fmt"
)

func UnmarshalWithCustomFields(data []byte, v interface{}, cf map[string]interface{}) error {
	// 向v中填充数据
	err := json.Unmarshal(data, v)
	if err != nil {
		return err
	}

	vData, err := json.Marshal(v)
	if err != nil {
		return err
	}

	var vf map[string]interface{}
	err = json.Unmarshal(vData, &vf)
	if err != nil {
		return err
	}

	var af map[string]interface{}
	err = json.Unmarshal(data, &af)
	if err != nil {
		return err
	}

	for k, v := range af {
		if _, ok := vf[k]; !ok {
			cf[k] = v
		}
	}

	return nil
}

func MarshalWithCustomFields(v interface{}, cf map[string]interface{}) ([]byte, error) {
	vm, err := MergeCustomFields(v, cf)
	if err != nil {
		return nil, err
	}

	return json.Marshal(vm)
}

func MergeCustomFields(v interface{}, cf map[string]interface{}) (map[string]interface{}, error) {
	fmt.Printf("v = %p, cf = %p\n", &v, cf)
	kf, err := ToMap(v)
	if err != nil {
		return nil, err
	}

	for key, val := range cf {
		if _, exists := kf[key]; !exists {
			kf[key] = val
		}
	}

	fmt.Printf("kf = %p\n", kf)
	return kf, nil
}

func ToMap(v interface{}) (map[string]interface{}, error) {
	var (
		b   []byte
		err error
	)

	switch cv := v.(type) {
	case []byte:
		b = cv
	case string:
		b = []byte(cv)
	default:
		b, err = json.Marshal(cv)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal value, err = %w", err)
		}
	}

	m := make(map[string]interface{})

	err = json.Unmarshal(b, &m)
	if err != nil {
		return nil, err
	}

	return m, nil
}
