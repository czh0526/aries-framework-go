package did

func LookupPublicKey(id string, didDoc *Doc) (*VerificationMethod, bool) {
	for _, key := range didDoc.VerificationMethod {
		if key.ID == id {
			return &key, true
		}
	}
	return nil, false
}

func ContextPeekString(context Context) (string, bool) {
	switch ctx := context.(type) {
	case string:
		if len(ctx) > 0 {
			return ctx, true
		}
	case []string:
		if len(ctx) > 0 {
			return ctx[0], true
		}
	case []interface{}:
		if len(ctx) > 0 {
			if strval, ok := ctx[0].(string); ok {
				return strval, true
			}
		}
	}

	return "", false
}

func ContextContainsString(context Context, contextString string) bool {
	var have []string
	switch ctx := context.(type) {
	case string:
		have = append(have, ctx)
	case []string:
		have = append(have, ctx...)
	case []interface{}:
		for _, val := range ctx {
			if strval, ok := val.(string); ok {
				have = append(have, strval)
			}
		}
	}

	for _, item := range have {
		if item == contextString {
			return true
		}
	}

	return false
}

func ContextCopy(context Context) Context {
	switch ctx := context.(type) {
	case string:
		return ctx
	case []string:
		var newContext []string
		newContext = append(newContext, ctx...)
		return newContext

	case []interface{}:
		var newContext []interface{}

		for _, v := range ctx {
			switch value := v.(type) {
			case string:
				newContext = append(newContext, value)
			case map[string]interface{}:
				newValue := map[string]interface{}{}
				for k, v := range value {
					newValue[k] = v
				}
				newContext = append(newContext, newValue)
			}
		}

		return newContext
	}

	return context
}

func ContextCleanup(context Context) Context {
	context = ContextCopy(context)

	switch ctx := context.(type) {
	case string:
		return ctx
	case []string:
		if len(ctx) == 0 {
			return []string{""}
		}
		return ctx

	case []interface{}:
		if len(ctx) == 0 {
			return ""
		}

		var newContext []string

		for _, item := range ctx {
			strVal, ok := item.(string)
			if !ok {
				return ctx
			}

			newContext = append(newContext, strVal)
		}

		return newContext
	}

	return context
}
