package maphelpers

import (
	"fmt"
	josejwt "github.com/go-jose/go-jose/v3/jwt"
	"github.com/mitchellh/mapstructure"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// JSONNumberToJwtNumericDate hook for mapstructure library to decode json.Number to jwt.NumericDate.
func JSONNumberToJwtNumericDate() mapstructure.DecodeHookFuncType {
	return func(
		f reflect.Type,
		t reflect.Type,
		data interface{},
	) (interface{}, error) {
		if f.String() != "json.Number" || !strings.Contains("jwt.NumericDate", t.String()) {
			return data, nil
		}

		parsedFloat, err := strconv.ParseFloat(fmt.Sprint(data), 64)
		if err != nil {
			return nil, err
		}

		date := josejwt.NewNumericDate(time.Unix(int64(parsedFloat), 0))

		if t.String() == "jwt.NumericDate" {
			return date, nil
		}

		return &date, nil
	}
}
