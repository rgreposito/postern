package ticket

import (
	"bytes"
	"testing"
	"time"
)

func TestIssueVerify(t *testing.T) {
	key := bytes.Repeat([]byte("k"), 32)
	m, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	tok, err := m.Issue(Claims{
		SID:      "abc",
		Grant:    "db-prod",
		SPIFFE:   "spiffe://prod/x",
		Action:   "connect",
		Resource: "tcp://db:5432",
		NBF:      now.Add(-time.Second).Unix(),
		EXP:      now.Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.Verify(tok, now, "tcp://db:5432")
	if err != nil {
		t.Fatal(err)
	}
	if got.SID != "abc" {
		t.Fatalf("%+v", got)
	}

	if _, err := m.Verify(tok, now.Add(2*time.Minute), "tcp://db:5432"); err != ErrExpired {
		t.Fatalf("want expired, got %v", err)
	}
	if _, err := m.Verify(tok, now, "tcp://other:5432"); err != ErrAudience {
		t.Fatalf("want audience, got %v", err)
	}

	tampered := tok[:len(tok)-2] + "aa"
	if _, err := m.Verify(tampered, now, "tcp://db:5432"); err != ErrMAC && err != ErrBad {
		t.Fatalf("want mac/bad, got %v", err)
	}
}

func TestShortKeyRejected(t *testing.T) {
	if _, err := New([]byte("tiny")); err == nil {
		t.Fatal("expected error")
	}
}
