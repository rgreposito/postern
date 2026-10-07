#!/usr/bin/env python3
"""Ask postern for an MCP tool grant, then pretend to call the tool.

This is the whole integration on the agent side: you do not inherit a
human's cookie. You present an agent id and a tool name.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

BASE = os.environ.get("POSTERN_URL", "http://127.0.0.1:8443")


def grant(agent: str, server: str, tool: str, data_class: str, rows: int) -> dict:
    body = json.dumps(
        {
            "kind": "agent",
            "principal": agent,
            "action": "invoke",
            "resource": f"mcp://{server}.{tool}",
            "tool": f"{server}.{tool}" if "." not in tool else tool,
            "data_class": data_class,
            "want_rows": rows,
            "exfil": False,
        }
    ).encode()
    req = urllib.request.Request(
        BASE + "/v1/grants",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        sys.stderr.write(e.read().decode() + "\n")
        raise SystemExit(e.code)


if __name__ == "__main__":
    out = grant(
        agent=os.environ.get("AGENT_ID", "agent://soc-triage"),
        server="splunk",
        tool="query",
        data_class="security-logs",
        rows=20,
    )
    # the ticket is what you'd pass to the MCP gateway, not the cert,
    # unless the gateway actually speaks mTLS. most of them don't yet.
    print(json.dumps({"allowed": out.get("allowed"), "grant_id": out.get("grant_id"),
                      "session_id": out.get("session_id"), "expires_at": out.get("expires_at")},
                     indent=2))
