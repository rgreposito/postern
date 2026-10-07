package session

import (
	"testing"
	"time"
)

func TestIssueExpireRevoke(t *testing.T) {
	now := time.Date(2026, 4, 2, 8, 0, 0, 0, time.UTC)
	clk := now
	st := NewStore(func() time.Time { return clk })

	got, err := st.Issue(Session{
		GrantID:   "db-prod",
		Principal: "spiffe://prod/ns/pay/sa/ledger",
		Kind:      "workload",
		Action:    "connect",
		Resource:  "tcp://db:5432",
		ExpiresAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.State != StateActive {
		t.Fatalf("state %s", got.State)
	}

	clk = now.Add(2 * time.Minute)
	loaded, err := st.Get(got.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.State != StateExpired {
		t.Fatalf("want expired, got %s", loaded.State)
	}

	clk = now
	live, err := st.Issue(Session{
		GrantID:   "db-prod",
		Principal: "spiffe://prod/ns/pay/sa/ledger",
		ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	rev, err := st.Revoke(live.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rev.State != StateRevoked {
		t.Fatalf("want revoked, got %s", rev.State)
	}
}

func TestJitterShortens(t *testing.T) {
	ttl := 10 * time.Minute
	now := time.Unix(1_700_000_123, 42)
	got := Jitter(ttl, now)
	if got >= ttl || got < ttl-ttl/10-ttl/20 {
		t.Fatalf("jitter out of range: %s", got)
	}
}
