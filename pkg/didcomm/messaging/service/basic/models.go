package basic

import "time"

type Message struct {
	ID   string `json:"@id"`
	Type string `json:"@type"`
	I10n struct {
		Locale string `json:"locale"`
	} `json:"~i10n"`
	SentTime time.Time `json:"sent_time"`
	Content  string    `json:"content"`
}
