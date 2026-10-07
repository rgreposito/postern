package ticket

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrBad      = errors.New("ticket: malformed")
	ErrMAC      = errors.New("ticket: bad mac")
	ErrExpired  = errors.New("ticket: expired")
	ErrNotYet   = errors.New("ticket: not yet valid")
	ErrAudience = errors.New("ticket: audience mismatch")
)

// Claims are what the data plane needs to enforce without calling
// the control plane on every connect. Keep this small; every field
// is a thing an attacker will try to confuse.
type Claims struct {
	SID       string `json:"sid"`
	Grant     string `json:"g"`
	SPIFFE    string `json:"spiffe"`
	Action    string `json:"act"`
	Resource  string `json:"res"`
	NBF       int64  `json:"nbf"`
	EXP       int64  `json:"exp"`
	Record    bool   `json:"rec,omitempty"`
	DenyExfil bool   `json:"nx,omitempty"`
	MaxRows   int    `json:"mr,omitempty"`
}

type Mint struct {
	key []byte
}

func New(key []byte) (*Mint, error) {
	if len(key) < 32 {
		return nil, errors.New("ticket: key must be at least 32 bytes")
	}
	return &Mint{key: key}, nil
}

func (m *Mint) Issue(c Claims) (string, error) {
	if c.SID == "" || c.SPIFFE == "" || c.Resource == "" {
		return "", fmt.Errorf("%w: missing fields", ErrBad)
	}
	body, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, m.key)
	mac.Write(body)
	return base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (m *Mint) Verify(tok string, now time.Time, resource string) (Claims, error) {
	var zero Claims
	parts := strings.Split(tok, ".")
	if len(parts) != 2 {
		return zero, ErrBad
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return zero, ErrBad
	}
	want, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return zero, ErrBad
	}
	mac := hmac.New(sha256.New, m.key)
	mac.Write(body)
	if !hmac.Equal(mac.Sum(nil), want) {
		return zero, ErrMAC
	}
	var c Claims
	if err := json.Unmarshal(body, &c); err != nil {
		return zero, ErrBad
	}
	unix := now.Unix()
	if unix < c.NBF {
		return zero, ErrNotYet
	}
	if unix >= c.EXP {
		return zero, ErrExpired
	}
	if resource != "" && c.Resource != resource {
		return zero, ErrAudience
	}
	return c, nil
}
