package agentid

import (
	"strings"
	"testing"

	"github.com/rgreposito/postern/internal/policy"
)

func TestResource(t *testing.T) {
	if Resource("splunk", "query") != "mcp://splunk.query" {
		t.Fatal(Resource("splunk", "query"))
	}
}

func TestExplain(t *testing.T) {
	if !strings.Contains(Explain(policy.Decision{Allow: false, Reason: "no matching grant"}), "deny") {
		t.Fatal("expected deny text")
	}
	if !strings.Contains(Explain(policy.Decision{Allow: true, GrantID: "soc-splunk"}), "soc-splunk") {
		t.Fatal("expected grant id")
	}
}
