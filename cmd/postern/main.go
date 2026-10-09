package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rgreposito/postern/internal/audit"
	"github.com/rgreposito/postern/internal/broker"
	"github.com/rgreposito/postern/internal/certs"
	"github.com/rgreposito/postern/internal/config"
	"github.com/rgreposito/postern/internal/policy"
	"github.com/rgreposito/postern/internal/session"
	"github.com/rgreposito/postern/internal/ticket"
)

func main() {
	os.Exit(run())
}

func run() int {
	var policyPath string
	flag.StringVar(&policyPath, "policy", "", "path to policy yaml (overrides POSTERN_POLICY)")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := config.FromEnv()
	if err != nil {
		log.Error("config", "err", err)
		return 2
	}
	if policyPath != "" {
		cfg.PolicyPath = policyPath
	}

	doc, err := policy.LoadFile(cfg.PolicyPath)
	if err != nil {
		log.Error("policy", "err", err, "path", cfg.PolicyPath)
		return 2
	}

	var auditW *os.File = os.Stdout
	if cfg.AuditPath != "" {
		f, err := os.OpenFile(cfg.AuditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			log.Error("audit file", "err", err)
			return 2
		}
		defer f.Close()
		auditW = f
	}

	now := time.Now()
	ca, err := certs.NewCA(now)
	if err != nil {
		log.Error("ca", "err", err)
		return 2
	}
	tm, err := ticket.New(cfg.TicketKey)
	if err != nil {
		log.Error("ticket key", "err", err)
		return 2
	}
	store := session.NewStore(time.Now)
	b := broker.New(doc, store, ca, tm, audit.New(auditW, cfg.FailClosed), log)

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           b.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				next, err := policy.LoadFile(cfg.PolicyPath)
				if err != nil {
					log.Error("reload", "err", err)
					continue
				}
				b.Reload(next)
				log.Info("reload", "grants", len(next.Grants), "path", cfg.PolicyPath)
			}
		}
	}()

	go func() {
		t := time.NewTicker(cfg.SweepEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				n := store.Sweep()
				if n > 0 {
					log.Info("sweep", "expired", n)
				}
			}
		}
	}()

	errCh := make(chan error, 1)
	go func() {
		log.Info("listen", "addr", cfg.Listen, "policy", cfg.PolicyPath, "grants", len(doc.Grants))
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shctx)
		return 0
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			log.Error("http", "err", err)
			return 1
		}
	}
	return 0
}
