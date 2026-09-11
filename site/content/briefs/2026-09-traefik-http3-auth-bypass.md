---
title: Traefik HTTP/3 Backend Authentication Bypass via Connection Reuse
slug: 2026-09-traefik-http3-auth-bypass
description: Traefik fails to isolate connection-bound NTLM and Negotiate authentication on HTTP/3 routes, allowing unrelated clients to inherit victim-authenticated backend connections.
date: "2026-09-11T00:52:59Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:traefik:traefik:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - auth-bypass
  - webserver
  - proxy
vendors:
  - Traefik
products:
  - Traefik (v2.11.0-v2.11.56)
  - Traefik (v3.0.0-v3.7.12)
cves:
  - id: CVE-2026-88007
references:
  - https://github.com/advisories/GHSA-qqjf-53cj-pwvv
  - https://github.com/traefik/traefik/releases/tag/v2.11.57
  - https://github.com/traefik/traefik/releases/tag/v3.7.13
  - https://nvd.nist.gov/vuln/detail/CVE-2026-88007
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Traefik instances to v2.11.57 or v3.7.13
      owner: IT Operations
      due: 24h
      evidence: Vendor patch availability
  mitigation_plan:
    - priority: immediate
      action: Disable HTTP/3 on Traefik entrypoints utilizing NTLM or Negotiate
      owner: IT Operations
      addresses: CVE-2026-88007
      evidence: Source workaround description
---

Traefik (v2.11.0-v2.11.56 and v3.0.0-v3.7.12) contains a critical authorization bypass vulnerability (CVE-2026-88007) when configured with HTTP/3. The vulnerability stems from a protocol-parity gap where the HTTP/3 entrypoint fails to initialize a connection-scoped transport holder, unlike the HTTP/1.1 and HTTP/2 paths. 

When using backends that utilize connection-bound authentication mechanisms such as NTLM or Negotiate (Kerberos), the `kerberosRoundTripper` relies on `service.AddTransportOnContext` to isolate authenticated connections. Because this initialization is absent in the HTTP/3 `ConnContext`, the round-tripper falls back to a shared backend transport pool. As a result, once a victim establishes an authenticated session to a backend that supports keep-alive, an unrelated HTTP/3 client may be assigned the same persistent backend TCP connection. This allows the second client to inherit the victim's backend identity, enabling unauthorized access to data and the ability to perform state-changing requests without providing the victim's credentials.

## Impact

Successful exploitation allows for complete cross-client authorization bypass on affected routes. An unauthenticated attacker can masquerade as a previously authenticated victim, enabling the theft of victim-only data and the execution of unauthorized actions (e.g., balance transfers or configuration changes). This affects enterprise environments utilizing NTLM or Kerberos authentication integrated with Traefik proxies and HTTP/3.

## Recommendation

- Upgrade Traefik to v2.11.57 or v3.7.13 immediately to ensure the `ConnContext` properly initializes the connection-scoped transport holder.
- As a temporary mitigation, disable HTTP/3 support on Traefik entrypoints that route to backends relying on connection-bound NTLM or Negotiate authentication until patches are applied.
- Audit backend configurations to identify services using persistent NTLM/Negotiate authentication and verify that they are not exposed via HTTP/3 entrypoints in the interim.
