export type PrincipalKind = "human" | "workload" | "agent";

export interface GrantRequest {
  kind: PrincipalKind;
  principal: string;
  action: string;
  resource: string;
  ttl?: string;
  attrs?: Record<string, string>;
  data_class?: string;
  tool?: string;
  want_rows?: number;
  exfil?: boolean;
}

export interface Grant {
  allowed: boolean;
  reason: string;
  grant_id?: string;
  session_id?: string;
  ticket?: string;
  expires_at?: string;
  spiffe?: string;
  record_session?: boolean;
}

export class Postern {
  constructor(private readonly baseUrl: string, private readonly fetchImpl: typeof fetch = fetch) {}

  async grant(req: GrantRequest): Promise<Grant> {
    const res = await this.fetchImpl(this.baseUrl.replace(/\/$/, "") + "/v1/grants", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(req),
    });
    const body = (await res.json()) as Grant;
    if (!res.ok && res.status !== 403) {
      throw new Error(`postern: ${res.status} ${body.reason ?? res.statusText}`);
    }
    return body;
  }

  async revoke(sessionId: string): Promise<void> {
    const res = await this.fetchImpl(
      this.baseUrl.replace(/\/$/, "") + "/v1/sessions/" + encodeURIComponent(sessionId) + "/revoke",
      { method: "POST" },
    );
    if (!res.ok) {
      throw new Error(`postern revoke: ${res.status}`);
    }
  }
}
