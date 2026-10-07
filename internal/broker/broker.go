package broker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/rgreposito/postern/internal/audit"
	"github.com/rgreposito/postern/internal/certs"
	"github.com/rgreposito/postern/internal/identity"
	"github.com/rgreposito/postern/internal/policy"
	"github.com/rgreposito/postern/internal/session"
	"github.com/rgreposito/postern/internal/ticket"
)

var ErrDenied = errors.New("broker: denied")

type GrantInput struct {
	Kind      string            `json:"kind"`
	Principal string            `json:"principal"`
	Action    string            `json:"action"`
	Resource  string            `json:"resource"`
	TTL       string            `json:"ttl,omitempty"`
	Attrs     map[string]string `json:"attrs,omitempty"`
	DataClass string            `json:"data_class,omitempty"`
	Tool      string            `json:"tool,omitempty"`
	WantRows  int               `json:"want_rows,omitempty"`
	Exfil     bool              `json:"exfil,omitempty"`
}

type GrantOutput struct {
	Allowed   bool          `json:"allowed"`
	Reason    string        `json:"reason"`
	GrantID   string        `json:"grant_id,omitempty"`
	SessionID string        `json:"session_id,omitempty"`
	Ticket    string        `json:"ticket,omitempty"`
	ExpiresAt *time.Time    `json:"expires_at,omitempty"`
	TTL       time.Duration `json:"-"`
	CertPEM   string        `json:"cert_pem,omitempty"`
	KeyPEM    string        `json:"key_pem,omitempty"`
	CAPEM     string        `json:"ca_pem,omitempty"`
	SPIFFE    string        `json:"spiffe,omitempty"`
	Record    bool          `json:"record_session,omitempty"`
}

type Broker struct {
	doc     *policy.Document
	store   *session.Store
	ca      *certs.CA
	tickets *ticket.Mint
	audit   *audit.Logger
	log     *slog.Logger
	now     func() time.Time
}

func New(doc *policy.Document, store *session.Store, ca *certs.CA, tickets *ticket.Mint, alog *audit.Logger, log *slog.Logger) *Broker {
	if log == nil {
		log = slog.Default()
	}
	return &Broker{
		doc:     doc,
		store:   store,
		ca:      ca,
		tickets: tickets,
		audit:   alog,
		log:     log,
		now:     time.Now,
	}
}

func (b *Broker) Grant(_ context.Context, in GrantInput) (GrantOutput, error) {
	p, err := identity.Parse(in.Kind, in.Principal)
	if err != nil {
		return GrantOutput{Reason: err.Error()}, err
	}
	ttl := time.Duration(0)
	if in.TTL != "" {
		ttl, err = time.ParseDuration(in.TTL)
		if err != nil {
			return GrantOutput{Reason: "bad ttl"}, err
		}
	}
	req := policy.Request{
		PrincipalKind: string(p.Kind),
		PrincipalID:   p.ID,
		Action:        in.Action,
		Resource:      in.Resource,
		TTL:           ttl,
		Attrs:         in.Attrs,
		DataClass:     in.DataClass,
		Tool:          in.Tool,
		WantRows:      in.WantRows,
		Exfil:         in.Exfil,
	}
	dec := b.doc.Evaluate(req)
	now := b.now()
	if !dec.Allow {
		_ = b.audit.MustEmit(audit.Event{
			Time:      now,
			Type:      "grant.deny",
			Decision:  "deny",
			GrantID:   dec.GrantID,
			Reason:    dec.Reason,
			Principal: p.ID,
			Kind:      string(p.Kind),
			Action:    in.Action,
			Resource:  in.Resource,
		})
		return GrantOutput{Allowed: false, Reason: dec.Reason, GrantID: dec.GrantID}, fmt.Errorf("%w: %s", ErrDenied, dec.Reason)
	}

	exp := now.Add(session.Jitter(dec.TTL, now))
	sess, err := b.store.Issue(session.Session{
		GrantID:   dec.GrantID,
		Principal: p.ID,
		Kind:      string(p.Kind),
		Action:    in.Action,
		Resource:  in.Resource,
		Record:    dec.Record,
		ExpiresAt: exp,
	})
	if err != nil {
		return GrantOutput{}, err
	}

	claims := ticket.Claims{
		SID:      sess.ID,
		Grant:    dec.GrantID,
		SPIFFE:   p.SPIFFE(),
		Action:   in.Action,
		Resource: in.Resource,
		NBF:      now.Add(-30 * time.Second).Unix(),
		EXP:      exp.Unix(),
		Record:   dec.Record,
	}
	if dec.Constraints != nil {
		claims.DenyExfil = dec.Constraints.DenyExfil
		claims.MaxRows = dec.Constraints.MaxRows
	}
	tok, err := b.tickets.Issue(claims)
	if err != nil {
		return GrantOutput{}, err
	}

	bundle, err := b.ca.Mint(p.SPIFFE(), exp.Sub(now), now)
	if err != nil {
		return GrantOutput{}, err
	}

	if err := b.audit.MustEmit(audit.Event{
		Time:      now,
		Type:      "grant.allow",
		Decision:  "allow",
		GrantID:   dec.GrantID,
		Reason:    dec.Reason,
		Principal: p.ID,
		Kind:      string(p.Kind),
		Action:    in.Action,
		Resource:  in.Resource,
		SessionID: sess.ID,
		TTLMS:     dec.TTL.Milliseconds(),
	}); err != nil {
		// fail-closed: we already minted. revoke so we don't leave
		// a live session without an audit row.
		_, _ = b.store.Revoke(sess.ID)
		return GrantOutput{}, fmt.Errorf("audit failed, grant aborted: %w", err)
	}

	b.log.Info("grant", "grant", dec.GrantID, "principal", p.ID, "resource", in.Resource, "ttl", dec.TTL)
	return GrantOutput{
		Allowed:   true,
		Reason:    dec.Reason,
		GrantID:   dec.GrantID,
		SessionID: sess.ID,
		Ticket:    tok,
		ExpiresAt: &exp,
		TTL:       dec.TTL,
		CertPEM:   string(bundle.CertPEM),
		KeyPEM:    string(bundle.KeyPEM),
		CAPEM:     string(bundle.CAPEM),
		SPIFFE:    p.SPIFFE(),
		Record:    dec.Record,
	}, nil
}

func (b *Broker) Revoke(_ context.Context, sessionID string) error {
	sess, err := b.store.Revoke(sessionID)
	if err != nil {
		return err
	}
	return b.audit.MustEmit(audit.Event{
		Type:      "session.revoke",
		Principal: sess.Principal,
		Kind:      sess.Kind,
		Action:    sess.Action,
		Resource:  sess.Resource,
		SessionID: sess.ID,
		GrantID:   sess.GrantID,
	})
}

func (b *Broker) Reload(doc *policy.Document) {
	b.doc = doc
}
