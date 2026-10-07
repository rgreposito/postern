package audit

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestEmitJSONLine(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, true)
	l.now = func() time.Time { return time.Unix(1_800_000_000, 0).UTC() }
	if err := l.Emit(Event{
		Type:      "grant.deny",
		Principal: "spiffe://prod/x",
		Kind:      "workload",
		Action:    "connect",
		Resource:  "tcp://db:5432",
		Reason:    "no matching grant",
	}); err != nil {
		t.Fatal(err)
	}
	line := buf.String()
	if !strings.HasSuffix(line, "\n") {
		t.Fatal("expected newline")
	}
	if !strings.Contains(line, `"type":"grant.deny"`) {
		t.Fatal(line)
	}
}
