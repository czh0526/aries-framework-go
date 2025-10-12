package service

import (
	"fmt"
	"testing"
)

type Inner struct {
	Name string `json:"name,omitempty"`
	Age  int    `json:"age"`
}

type Outer struct {
	Inner      `json:"inner"`
	Title      string `json:"title"`
	Hidden     int    `json:"hidden"`
	unexported string `json:"unexported"`
}

func TestToMap(t *testing.T) {
	outer := Outer{}

	m := toMap(outer)

	fmt.Println(m)
}
