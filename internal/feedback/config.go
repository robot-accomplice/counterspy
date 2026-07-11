// internal/feedback/config.go
package feedback

import (
	"encoding/json"
	"os"
)

// Share is the three-way consent level. Default (and any invalid value) is off.
const (
	ShareOff    = "off"    // never touches the network (default)
	ShareAsk    = "ask"    // show exact records, confirm each session
	ShareAlways = "always" // standing consent
)

// Config is the user's feedback preference, stored under the invoking user's home.
type Config struct {
	Share    string `json:"share"`
	Detail   Detail `json:"detail"`
	Endpoint string `json:"endpoint"`
}

// LoadConfig reads the config, failing safe to off/public on any error or unknown value —
// a fresh install shares nothing until the user explicitly opts in.
func LoadConfig(path string) Config {
	c := Config{Share: ShareOff, Detail: DetailPublic}
	b, err := os.ReadFile(path)
	if err != nil {
		return c
	}
	var raw Config
	if json.Unmarshal(b, &raw) != nil {
		return c
	}
	switch raw.Share {
	case ShareAsk, ShareAlways:
		c.Share = raw.Share
	}
	if raw.Detail == DetailFull {
		c.Detail = DetailFull
	}
	c.Endpoint = raw.Endpoint
	return c
}
