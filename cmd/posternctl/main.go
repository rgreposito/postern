package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: posternctl <grant|revoke|verify|sessions> ...")
	}
	base := env("POSTERN_URL", "http://127.0.0.1:8443")
	switch args[0] {
	case "grant":
		return grant(base, args[1:])
	case "revoke":
		return revoke(base, args[1:])
	case "verify":
		return verify(base, args[1:])
	case "sessions":
		return sessions(base)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func grant(base string, args []string) error {
	fs := flag.NewFlagSet("grant", flag.ContinueOnError)
	kind := fs.String("kind", "human", "human|workload|agent")
	principal := fs.String("principal", "", "id")
	action := fs.String("action", "connect", "")
	resource := fs.String("resource", "", "")
	ttl := fs.String("ttl", "", "requested ttl, e.g. 5m")
	mfa := fs.String("mfa", "", "")
	posture := fs.String("device-posture", "", "")
	network := fs.String("network", "", "")
	tool := fs.String("tool", "", "")
	dataClass := fs.String("data-class", "", "")
	rows := fs.Int("rows", 0, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *principal == "" || *resource == "" {
		return fmt.Errorf("grant: -principal and -resource are required")
	}
	payload := map[string]any{
		"kind":      *kind,
		"principal": *principal,
		"action":    *action,
		"resource":  *resource,
	}
	if *ttl != "" {
		payload["ttl"] = *ttl
	}
	attrs := map[string]string{}
	if *mfa != "" {
		attrs["mfa"] = *mfa
	}
	if *posture != "" {
		attrs["device_posture"] = *posture
	}
	if *network != "" {
		attrs["network"] = *network
	}
	if len(attrs) > 0 {
		payload["attrs"] = attrs
	}
	if *tool != "" {
		payload["tool"] = *tool
	}
	if *dataClass != "" {
		payload["data_class"] = *dataClass
	}
	if *rows > 0 {
		payload["want_rows"] = *rows
	}
	var out map[string]any
	if err := post(base+"/v1/grants", payload, &out); err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func revoke(base string, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: posternctl revoke <session-id>")
	}
	var out map[string]any
	if err := post(base+"/v1/sessions/"+args[0]+"/revoke", map[string]any{}, &out); err != nil {
		return err
	}
	fmt.Println(out["status"], out["id"])
	return nil
}

func verify(base string, args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	tok := fs.String("ticket", "", "")
	res := fs.String("resource", "", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *tok == "" {
		return fmt.Errorf("verify: -ticket is required")
	}
	var out map[string]any
	if err := post(base+"/v1/tickets/verify", map[string]any{"ticket": *tok, "resource": *res}, &out); err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func sessions(base string) error {
	resp, err := http.Get(base + "/v1/sessions")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, err = io.Copy(os.Stdout, resp.Body)
	return err
}

func post(url string, payload any, dest any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(raw)))
	}
	if dest == nil {
		return nil
	}
	return json.Unmarshal(raw, dest)
}

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}
