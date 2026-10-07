package broker

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

func (b *Broker) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", b.health)
	mux.HandleFunc("POST /v1/grants", b.handleGrant)
	mux.HandleFunc("POST /v1/sessions/{id}/revoke", b.handleRevoke)
	mux.HandleFunc("GET /v1/sessions", b.handleList)
	mux.HandleFunc("POST /v1/tickets/verify", b.handleVerify)
	return mux
}

func (b *Broker) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "ts": b.now().UTC()})
}

func (b *Broker) handleGrant(w http.ResponseWriter, r *http.Request) {
	var in GrantInput
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	out, err := b.Grant(r.Context(), in)
	if err != nil {
		code := http.StatusForbidden
		if !errors.Is(err, ErrDenied) {
			code = http.StatusBadRequest
		}
		writeJSON(w, code, out)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (b *Broker) handleRevoke(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing id"})
		return
	}
	if err := b.Revoke(r.Context(), id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked", "id": id})
}

func (b *Broker) handleList(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, b.store.ListActive())
}

type verifyIn struct {
	Ticket   string `json:"ticket"`
	Resource string `json:"resource"`
}

func (b *Broker) handleVerify(w http.ResponseWriter, r *http.Request) {
	var in verifyIn
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	claims, err := b.tickets.Verify(strings.TrimSpace(in.Ticket), b.now(), in.Resource)
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, claims)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// Compile-time reminder that GrantOutput's time fields should stay
// RFC3339. json.Encoder does that for time.Time already.
var _ = time.RFC3339
