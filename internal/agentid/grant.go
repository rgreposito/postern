package agentid

import (
	"fmt"
	"strings"

	"github.com/rgreposito/postern/internal/policy"
)

// ToolRequest is what an MCP-style agent presents when it wants to
// invoke a tool. We treat the tool name as the resource, not as an
// afterthought on a human session.
type ToolRequest struct {
	AgentID   string
	Server    string
	Tool      string
	DataClass string
	WantRows  int
	Exfil     bool
}

func Resource(server, tool string) string {
	server = strings.TrimSpace(server)
	tool = strings.TrimSpace(tool)
	if server == "" {
		return "mcp://" + tool
	}
	return "mcp://" + server + "." + tool
}

func ToPolicyRequest(r ToolRequest, ttl string) policy.Request {
	return policy.Request{
		PrincipalKind: "agent",
		PrincipalID:   r.AgentID,
		Action:        "invoke",
		Resource:      Resource(r.Server, r.Tool),
		Tool:          r.Tool,
		DataClass:     r.DataClass,
		WantRows:      r.WantRows,
		Exfil:         r.Exfil,
	}
}

// Explain is for operators, not for the agent. Agents get allow/deny.
// Humans debugging a 3am deny get a sentence.
func Explain(d policy.Decision) string {
	if d.Allow {
		msg := fmt.Sprintf("allow grant=%s ttl=%s", d.GrantID, d.TTL)
		if d.Constraints != nil && d.Constraints.MaxRows > 0 {
			msg += fmt.Sprintf(" max_rows=%d", d.Constraints.MaxRows)
		}
		return msg
	}
	if d.GrantID != "" {
		return fmt.Sprintf("deny grant=%s reason=%s", d.GrantID, d.Reason)
	}
	return "deny reason=" + d.Reason
}
