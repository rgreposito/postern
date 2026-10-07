package identity

import "testing"

func TestParse(t *testing.T) {
	ok, err := Parse("workload", "spiffe://prod/ns/pay/sa/ledger")
	if err != nil {
		t.Fatal(err)
	}
	if ok.SPIFFE() != ok.ID {
		t.Fatalf("workload spiffe should be the id itself")
	}

	h, err := Parse("human", "rafa@corp.example")
	if err != nil {
		t.Fatal(err)
	}
	if h.SPIFFE() != "spiffe://postern/human/rafa@corp.example" {
		t.Fatalf("got %s", h.SPIFFE())
	}

	a, err := Parse("agent", "agent://soc-triage")
	if err != nil {
		t.Fatal(err)
	}
	if a.SPIFFE() != "spiffe://postern/agent/soc-triage" {
		t.Fatalf("got %s", a.SPIFFE())
	}

	if _, err := Parse("workload", "not-a-spiffe"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := Parse("cat", "x"); err == nil {
		t.Fatal("expected error")
	}
}
