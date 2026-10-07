package identity

import (
	"errors"
	"fmt"
	"strings"
)

type Kind string

const (
	KindHuman    Kind = "human"
	KindWorkload Kind = "workload"
	KindAgent    Kind = "agent"
)

var ErrInvalid = errors.New("identity: invalid principal")

// Principal is whoever is asking. Keep this boring. The interesting
// part is that agents are not a bolt-on attribute on a human — they
// have their own kind, their own id scheme, their own grants.
type Principal struct {
	Kind  Kind
	ID    string
	Attrs map[string]string
}

func Parse(kind, id string) (Principal, error) {
	k := Kind(kind)
	switch k {
	case KindHuman, KindWorkload, KindAgent:
	default:
		return Principal{}, fmt.Errorf("%w: kind %q", ErrInvalid, kind)
	}
	if id == "" {
		return Principal{}, fmt.Errorf("%w: empty id", ErrInvalid)
	}
	if err := validateID(k, id); err != nil {
		return Principal{}, err
	}
	return Principal{Kind: k, ID: id, Attrs: map[string]string{}}, nil
}

func validateID(k Kind, id string) error {
	switch k {
	case KindWorkload:
		if !strings.HasPrefix(id, "spiffe://") {
			return fmt.Errorf("%w: workload id must be a spiffe uri, got %q", ErrInvalid, id)
		}
	case KindAgent:
		if !strings.HasPrefix(id, "agent://") {
			return fmt.Errorf("%w: agent id must be agent://..., got %q", ErrInvalid, id)
		}
	case KindHuman:
		if !strings.Contains(id, "@") {
			return fmt.Errorf("%w: human id must look like an email, got %q", ErrInvalid, id)
		}
	}
	if strings.ContainsAny(id, " \t\n") {
		return fmt.Errorf("%w: id contains whitespace", ErrInvalid)
	}
	return nil
}

func (p Principal) SPIFFE() string {
	switch p.Kind {
	case KindWorkload:
		return p.ID
	case KindHuman:
		return "spiffe://postern/human/" + p.ID
	case KindAgent:
		return "spiffe://postern/agent/" + strings.TrimPrefix(p.ID, "agent://")
	default:
		return ""
	}
}
