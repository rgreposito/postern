package policy

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Document is the on-disk policy. Version is currently 1; unknown
// versions are rejected rather than best-effort parsed.
type Document struct {
	Version int     `yaml:"version"`
	Grants  []Grant `yaml:"grants"`
}

type Grant struct {
	ID          string        `yaml:"id"`
	Principal   PrincipalSel  `yaml:"principal"`
	Action      string        `yaml:"action"`
	Resource    string        `yaml:"resource"`
	MaxTTL      Duration      `yaml:"max_ttl"`
	Require     []Requirement `yaml:"require,omitempty"`
	Record      bool          `yaml:"record_session,omitempty"`
	Constraints *Constraints  `yaml:"constraints,omitempty"`
	Comment     string        `yaml:"comment,omitempty"`
}

type PrincipalSel struct {
	Kind  string `yaml:"kind"`  // human | workload | agent
	Match string `yaml:"match"` // glob against the principal id
}

type Requirement struct {
	DevicePosture string `yaml:"device_posture,omitempty"`
	MFA           string `yaml:"mfa,omitempty"`
	Network       string `yaml:"network,omitempty"`
}

// Constraints are mostly for KindAgent. Humans/workloads can set
// them too; the evaluator does not special-case that.
type Constraints struct {
	DataClasses []string `yaml:"data_classes,omitempty"`
	DenyExfil   bool     `yaml:"deny_exfil,omitempty"`
	MaxRows     int      `yaml:"max_rows,omitempty"`
	Tools       []string `yaml:"tools,omitempty"`
}

func LoadFile(path string) (*Document, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(raw)
}

func Parse(raw []byte) (*Document, error) {
	var doc Document
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("policy parse: %w", err)
	}
	if err := doc.Validate(); err != nil {
		return nil, err
	}
	return &doc, nil
}

func (d *Document) Validate() error {
	if d.Version != 1 {
		return fmt.Errorf("policy: unsupported version %d (want 1)", d.Version)
	}
	if len(d.Grants) == 0 {
		return fmt.Errorf("policy: no grants; an empty file is not 'deny all', it's a misconfig")
	}
	seen := make(map[string]struct{}, len(d.Grants))
	for i, g := range d.Grants {
		if g.ID == "" {
			return fmt.Errorf("policy: grant[%d] missing id", i)
		}
		if _, ok := seen[g.ID]; ok {
			return fmt.Errorf("policy: duplicate grant id %q", g.ID)
		}
		seen[g.ID] = struct{}{}
		if err := g.validate(); err != nil {
			return fmt.Errorf("policy: grant %q: %w", g.ID, err)
		}
	}
	return nil
}

func (g Grant) validate() error {
	switch g.Principal.Kind {
	case "human", "workload", "agent":
	default:
		return fmt.Errorf("unknown principal kind %q", g.Principal.Kind)
	}
	if g.Principal.Match == "" {
		return fmt.Errorf("principal.match is required")
	}
	if g.Action == "" {
		return fmt.Errorf("action is required")
	}
	if g.Resource == "" {
		return fmt.Errorf("resource is required")
	}
	if g.MaxTTL.Duration() <= 0 {
		return fmt.Errorf("max_ttl is required")
	}
	if strings.ContainsAny(g.Resource, " \t") {
		return fmt.Errorf("resource must not contain whitespace")
	}
	return nil
}
