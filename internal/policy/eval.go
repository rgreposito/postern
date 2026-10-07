package policy

import (
	"errors"
	"fmt"
	"time"
)

var (
	ErrDenied      = errors.New("denied")
	ErrTTLTooLong  = errors.New("requested ttl exceeds grant")
	ErrUnsatisfied = errors.New("requirement not met")
	ErrConstraint  = errors.New("constraint violation")
)

// Request is what the broker asks the evaluator.
type Request struct {
	PrincipalKind string
	PrincipalID   string
	Action        string
	Resource      string
	TTL           time.Duration
	Attrs         map[string]string // device_posture, mfa, network, ...
	DataClass     string            // optional, agent-side
	Tool          string            // optional, agent-side
	WantRows      int               // optional, agent-side
	Exfil         bool
}

type Decision struct {
	Allow       bool
	GrantID     string
	TTL         time.Duration
	Record      bool
	Constraints *Constraints
	Reason      string
}

// Evaluate is first-match, deny-by-default.
//
// First-match is a conscious trade: most-specific-wins looks smarter
// until someone has to debug why grant B shadowed grant A at 3am.
// Put the tight grants first. See docs/adr/0001-policy-language.md.
func (d *Document) Evaluate(req Request) Decision {
	if req.PrincipalID == "" || req.Action == "" || req.Resource == "" {
		return Decision{Reason: "incomplete request"}
	}
	for _, g := range d.Grants {
		if !matchGrant(g, req) {
			continue
		}
		if err := checkRequirements(g.Require, req.Attrs); err != nil {
			return Decision{
				GrantID: g.ID,
				Reason:  err.Error(),
			}
		}
		if err := checkConstraints(g.Constraints, req); err != nil {
			return Decision{
				GrantID: g.ID,
				Reason:  err.Error(),
			}
		}
		ttl := req.TTL
		if ttl <= 0 || ttl > g.MaxTTL.Duration() {
			ttl = g.MaxTTL.Duration()
		}
		return Decision{
			Allow:       true,
			GrantID:     g.ID,
			TTL:         ttl,
			Record:      g.Record,
			Constraints: g.Constraints,
			Reason:      "matched " + g.ID,
		}
	}
	return Decision{Reason: "no matching grant"}
}

func matchGrant(g Grant, req Request) bool {
	if g.Principal.Kind != req.PrincipalKind {
		return false
	}
	if !Match(g.Principal.Match, req.PrincipalID) {
		return false
	}
	if !Match(g.Action, req.Action) {
		return false
	}
	if !Match(g.Resource, req.Resource) {
		return false
	}
	return true
}

func checkRequirements(reqs []Requirement, attrs map[string]string) error {
	if len(reqs) == 0 {
		return nil
	}
	if attrs == nil {
		attrs = map[string]string{}
	}
	for _, r := range reqs {
		if r.DevicePosture != "" && attrs["device_posture"] != r.DevicePosture {
			return fmt.Errorf("%w: device_posture want %q got %q", ErrUnsatisfied, r.DevicePosture, attrs["device_posture"])
		}
		if r.MFA != "" && attrs["mfa"] != r.MFA {
			return fmt.Errorf("%w: mfa want %q got %q", ErrUnsatisfied, r.MFA, attrs["mfa"])
		}
		if r.Network != "" && !Match(r.Network, attrs["network"]) {
			return fmt.Errorf("%w: network want %q got %q", ErrUnsatisfied, r.Network, attrs["network"])
		}
	}
	return nil
}

func checkConstraints(c *Constraints, req Request) error {
	if req.Exfil {
		// a client admitting exfil is refused even if the grant
		// forgot deny_exfil. belt and braces.
		return fmt.Errorf("%w: exfil not permitted", ErrConstraint)
	}
	if c == nil {
		return nil
	}
	if len(c.DataClasses) > 0 && req.DataClass != "" {
		if !contains(c.DataClasses, req.DataClass) {
			return fmt.Errorf("%w: data class %q not in grant", ErrConstraint, req.DataClass)
		}
	}
	if len(c.Tools) > 0 && req.Tool != "" {
		ok := false
		for _, t := range c.Tools {
			if Match(t, req.Tool) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("%w: tool %q not in grant", ErrConstraint, req.Tool)
		}
	}
	if c.MaxRows > 0 && req.WantRows > c.MaxRows {
		return fmt.Errorf("%w: rows %d > %d", ErrConstraint, req.WantRows, c.MaxRows)
	}
	return nil
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
