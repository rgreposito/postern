package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Listen       string
	PolicyPath   string
	TicketKey    []byte
	AuditPath    string
	FailClosed   bool
	SweepEvery   time.Duration
	PublicURL    string
}

func FromEnv() (Config, error) {
	c := Config{
		Listen:     getenv("POSTERN_LISTEN", "127.0.0.1:8443"),
		PolicyPath: getenv("POSTERN_POLICY", "policies/examples/prod.yaml"),
		AuditPath:  getenv("POSTERN_AUDIT", ""),
		PublicURL:  getenv("POSTERN_URL", "http://127.0.0.1:8443"),
		SweepEvery: 30 * time.Second,
		FailClosed: true,
	}
	if v := os.Getenv("POSTERN_FAIL_CLOSED"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return c, fmt.Errorf("POSTERN_FAIL_CLOSED: %w", err)
		}
		c.FailClosed = b
	}
	key := os.Getenv("POSTERN_TICKET_KEY")
	if key == "" {
		// 32 bytes, obviously not a secret. production must override.
		key = "dev-only-not-for-production-use!"
	}
	if len(key) < 32 {
		return c, fmt.Errorf("POSTERN_TICKET_KEY must be >= 32 bytes")
	}
	c.TicketKey = []byte(key)
	return c, nil
}

func getenv(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}
