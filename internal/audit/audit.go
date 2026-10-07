package audit

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

// Event is one line in the audit log. Field names stay stable; dashboards
// get built on them and then nobody can rename anything.
type Event struct {
	Time      time.Time `json:"ts"`
	Type      string    `json:"type"` // grant.allow | grant.deny | session.revoke | session.expire
	Decision  string    `json:"decision,omitempty"`
	GrantID   string    `json:"grant_id,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	Principal string    `json:"principal"`
	Kind      string    `json:"kind"`
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	SessionID string    `json:"session_id,omitempty"`
	TTLMS     int64     `json:"ttl_ms,omitempty"`
}

type Logger struct {
	w          io.Writer
	now        func() time.Time
	failClosed bool
	mu         sync.Mutex
}

func New(w io.Writer, failClosed bool) *Logger {
	if w == nil {
		w = os.Stdout
	}
	return &Logger{w: w, now: time.Now, failClosed: failClosed}
}

func (l *Logger) Emit(ev Event) error {
	if ev.Time.IsZero() {
		ev.Time = l.now()
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	l.mu.Lock()
	_, err = l.w.Write(b)
	l.mu.Unlock()
	if err != nil && !l.failClosed {
		return nil
	}
	return err
}

// MustEmit is for the broker hot path. failClosed means a full disk
// is a denied grant, not a silent hole in the log. that's the point.
func (l *Logger) MustEmit(ev Event) error {
	err := l.Emit(ev)
	if err != nil && l.failClosed {
		return err
	}
	return nil
}
