package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rgreposito/postern/internal/audit"
	"github.com/rgreposito/postern/internal/certs"
	"github.com/rgreposito/postern/internal/policy"
	"github.com/rgreposito/postern/internal/session"
	"github.com/rgreposito/postern/internal/ticket"
)

func testBroker(t *testing.T) *Broker {
	t.Helper()
	doc, err := policy.Parse([]byte(`
version: 1
grants:
  - id: db-prod
    principal: {kind: workload, match: spiffe://prod/**}
    action: connect
    resource: tcp://db.prod:5432
    max_ttl: 10m
  - id: soc
    principal: {kind: agent, match: agent://soc-*}
    action: invoke
    resource: mcp://splunk.query
    max_ttl: 5m
    constraints: {deny_exfil: true, max_rows: 50}
`))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	ca, err := certs.NewCA(now)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte("s"), 32)
	tm, err := ticket.New(key)
	if err != nil {
		t.Fatal(err)
	}
	b := New(doc, session.NewStore(func() time.Time { return now }), ca, tm, audit.New(io.Discard, true), slog.New(slog.NewTextHandler(io.Discard, nil)))
	b.now = func() time.Time { return now }
	return b
}

func TestGrantAndVerifyHTTP(t *testing.T) {
	b := testBroker(t)
	srv := httptest.NewServer(b.Handler())
	defer srv.Close()

	body := []byte(`{"kind":"workload","principal":"spiffe://prod/ns/pay/sa/ledger","action":"connect","resource":"tcp://db.prod:5432","ttl":"2m"}`)
	res, err := http.Post(srv.URL+"/v1/grants", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("status %d", res.StatusCode)
	}
	var out GrantOutput
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !out.Allowed || out.Ticket == "" || out.CertPEM == "" {
		t.Fatalf("incomplete grant: %+v", out)
	}

	vr, err := http.Post(srv.URL+"/v1/tickets/verify", "application/json", bytes.NewReader([]byte(
		`{"ticket":"`+out.Ticket+`","resource":"tcp://db.prod:5432"}`,
	)))
	if err != nil {
		t.Fatal(err)
	}
	defer vr.Body.Close()
	if vr.StatusCode != 200 {
		t.Fatalf("verify %d", vr.StatusCode)
	}
}

func TestDenyExfil(t *testing.T) {
	b := testBroker(t)
	_, err := b.Grant(context.Background(), GrantInput{
		Kind:      "agent",
		Principal: "agent://soc-triage",
		Action:    "invoke",
		Resource:  "mcp://splunk.query",
		Tool:      "splunk.query",
		Exfil:     true,
	})
	if err == nil {
		t.Fatal("exfil should be denied")
	}
}

func TestUnknownPrincipalDenied(t *testing.T) {
	b := testBroker(t)
	_, err := b.Grant(context.Background(), GrantInput{
		Kind:      "workload",
		Principal: "spiffe://staging/ns/pay/sa/ledger",
		Action:    "connect",
		Resource:  "tcp://db.prod:5432",
	})
	if err == nil {
		t.Fatal("expected deny")
	}
}

func TestReloadSwapsDocument(t *testing.T) {
	b := testBroker(t)
	next, err := policy.Parse([]byte(`
version: 1
grants:
  - id: staging-only
    principal: {kind: workload, match: spiffe://staging/**}
    action: connect
    resource: tcp://db.prod:5432
    max_ttl: 1m
`))
	if err != nil {
		t.Fatal(err)
	}
	b.Reload(next)
	_, err = b.Grant(context.Background(), GrantInput{
		Kind:      "workload",
		Principal: "spiffe://prod/ns/pay/sa/ledger",
		Action:    "connect",
		Resource:  "tcp://db.prod:5432",
	})
	if err == nil {
		t.Fatal("old grant should be gone after reload")
	}
	out, err := b.Grant(context.Background(), GrantInput{
		Kind:      "workload",
		Principal: "spiffe://staging/ns/pay/sa/ledger",
		Action:    "connect",
		Resource:  "tcp://db.prod:5432",
	})
	if err != nil || !out.Allowed {
		t.Fatalf("staging should be allowed after reload: %v %+v", err, out)
	}
}
