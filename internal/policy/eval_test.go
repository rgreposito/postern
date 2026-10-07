package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func sample(t *testing.T) *Document {
	t.Helper()
	raw := []byte(`
version: 1
grants:
  - id: db-prod
    principal:
      kind: workload
      match: spiffe://prod/ns/payments/**
    action: connect
    resource: tcp://ledger-db.prod.internal:5432
    max_ttl: 15m
    require:
      - network: "10.8.*"
    record_session: true
  - id: human-ssh
    principal:
      kind: human
      match: "*@corp.example"
    action: ssh
    resource: ssh://bastion.prod.internal
    max_ttl: 1h
    require:
      - mfa: webauthn
      - device_posture: ok
  - id: soc-splunk
    principal:
      kind: agent
      match: agent://soc-*
    action: invoke
    resource: mcp://splunk.*
    max_ttl: 5m
    constraints:
      data_classes: [security-logs]
      deny_exfil: true
      max_rows: 500
      tools: ["splunk.query", "splunk.stats"]
`)
	doc, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestEvaluateAllow(t *testing.T) {
	doc := sample(t)
	d := doc.Evaluate(Request{
		PrincipalKind: "workload",
		PrincipalID:   "spiffe://prod/ns/payments/sa/ledger",
		Action:        "connect",
		Resource:      "tcp://ledger-db.prod.internal:5432",
		TTL:           5 * time.Minute,
		Attrs:         map[string]string{"network": "10.8.12.4"},
	})
	if !d.Allow {
		t.Fatalf("want allow, got %+v", d)
	}
	if d.GrantID != "db-prod" {
		t.Fatalf("grant %s", d.GrantID)
	}
	if d.TTL != 5*time.Minute {
		t.Fatalf("ttl %s", d.TTL)
	}
	if !d.Record {
		t.Fatal("expected session recording")
	}
}

func TestEvaluateDenyNoGrant(t *testing.T) {
	doc := sample(t)
	d := doc.Evaluate(Request{
		PrincipalKind: "workload",
		PrincipalID:   "spiffe://staging/ns/payments/sa/ledger",
		Action:        "connect",
		Resource:      "tcp://ledger-db.prod.internal:5432",
	})
	if d.Allow {
		t.Fatalf("staging should not reach prod: %+v", d)
	}
}

func TestEvaluateRequirement(t *testing.T) {
	doc := sample(t)
	d := doc.Evaluate(Request{
		PrincipalKind: "human",
		PrincipalID:   "rafa@corp.example",
		Action:        "ssh",
		Resource:      "ssh://bastion.prod.internal",
		Attrs:         map[string]string{"mfa": "totp", "device_posture": "ok"},
	})
	if d.Allow {
		t.Fatal("totp should not satisfy webauthn")
	}
}

func TestEvaluateAgentConstraints(t *testing.T) {
	doc := sample(t)
	ok := doc.Evaluate(Request{
		PrincipalKind: "agent",
		PrincipalID:   "agent://soc-triage",
		Action:        "invoke",
		Resource:      "mcp://splunk.query",
		Tool:          "splunk.query",
		DataClass:     "security-logs",
		WantRows:      20,
	})
	if !ok.Allow {
		t.Fatalf("want allow: %+v", ok)
	}

	exfil := doc.Evaluate(Request{
		PrincipalKind: "agent",
		PrincipalID:   "agent://soc-triage",
		Action:        "invoke",
		Resource:      "mcp://splunk.query",
		Tool:          "splunk.query",
		DataClass:     "security-logs",
		Exfil:         true,
	})
	if exfil.Allow {
		t.Fatal("exfil must be denied")
	}

	rows := doc.Evaluate(Request{
		PrincipalKind: "agent",
		PrincipalID:   "agent://soc-triage",
		Action:        "invoke",
		Resource:      "mcp://splunk.query",
		Tool:          "splunk.query",
		DataClass:     "security-logs",
		WantRows:      5000,
	})
	if rows.Allow {
		t.Fatal("row budget should trip")
	}
}

func TestEvaluateCapsTTL(t *testing.T) {
	doc := sample(t)
	d := doc.Evaluate(Request{
		PrincipalKind: "workload",
		PrincipalID:   "spiffe://prod/ns/payments/sa/ledger",
		Action:        "connect",
		Resource:      "tcp://ledger-db.prod.internal:5432",
		TTL:           24 * time.Hour,
		Attrs:         map[string]string{"network": "10.8.0.1"},
	})
	if !d.Allow || d.TTL != 15*time.Minute {
		t.Fatalf("ttl should cap at grant max, got %+v", d)
	}
}

func TestLoadFileAndEmptyRejected(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "empty.yaml")
	if err := os.WriteFile(p, []byte("version: 1\ngrants: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(p); err == nil {
		t.Fatal("empty grants should be a misconfig")
	}
	if _, err := Parse([]byte("version: 2\ngrants:\n  - id: x\n")); err == nil {
		t.Fatal("v2 should be rejected")
	}
}

func BenchmarkEvaluate(b *testing.B) {
	t := &testing.T{}
	doc := sample(t)
	if t.Failed() {
		b.Fatal("sample fixture failed")
	}
	req := Request{
		PrincipalKind: "workload",
		PrincipalID:   "spiffe://prod/ns/payments/sa/ledger",
		Action:        "connect",
		Resource:      "tcp://ledger-db.prod.internal:5432",
		Attrs:         map[string]string{"network": "10.8.12.4"},
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = doc.Evaluate(req)
	}
}
