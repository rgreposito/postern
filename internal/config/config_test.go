package config

import (
	"os"
	"testing"
)

func TestFromEnvDevFallback(t *testing.T) {
	t.Setenv("POSTERN_TICKET_KEY", "")
	os.Unsetenv("POSTERN_TICKET_KEY")
	c, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.TicketKey) < 32 {
		t.Fatalf("dev fallback too short: %d", len(c.TicketKey))
	}
}

func TestFromEnvRejectsShortKey(t *testing.T) {
	t.Setenv("POSTERN_TICKET_KEY", "tiny")
	if _, err := FromEnv(); err == nil {
		t.Fatal("expected error")
	}
}
