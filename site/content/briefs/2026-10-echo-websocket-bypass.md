---
brief_id: brief-2026-10-23-echo-websocket-bypass
event_id: brief-2026-10-23-echo-websocket-bypass
revision: 2
activity_at: "2026-10-28T23:37:51Z"
revision_history:
  - revision: 2
    at: "2026-10-28T23:37:51Z"
    checksum: sha256:a77217e16bbf64aaa10774be82d6f21e6b67a8e1147b053535fb696fa73cfd1e
    summary: poc_available; added CVE-2026-118264
    changed_fields:
      - claim_state
      - cpes
      - cves
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-118264&utm_source=rss&utm_medium=rss
title: 'Labstack Echo: Proxy middleware WebSocket upgrade bypass'
slug: 2026-10-echo-websocket-bypass
description: The Labstack Echo web framework Proxy middleware incorrectly establishes a raw tunnel for WebSocket upgrades before validating upstream responses, allowing subsequent HTTP requests to bypass route-level authentication and authorization.
date: "2026-10-23T21:44:59Z"
lastmod: "2026-10-28T23:36:57Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Verified against GHSA advisory and vendor patch commits.
cpes:
  - cpe:2.3:a:labstack:echo:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-118264&utm_source=rss&utm_medium=rss
vendors:
  - Labstack
products:
  - Echo (v4 < 4.16.1)
  - Echo (v5 < 5.4.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This can bypass authentication or authorization enforced only at Echo's routes.
    confidence_band: high
cves:
  - id: CVE-2026-118264
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-cxf3-9h37-7rr8
  - https://github.com/labstack/echo/commit/3fb0ba7e17645bb65611e2a08875d0a2f65c421f
  - https://github.com/labstack/echo/commit/1855061e572ae9dab727c811d8382f266bfbaaec
  - https://github.com/labstack/echo/releases/tag/v4.16.1
  - https://github.com/labstack/echo/releases/tag/v5.4.1
  - https://pwn.watch/i/labstack-echo-proxy-websocket-auth-bypass-ghsa-cxf3-9h37-7rr8
  - https://github.com/labstack/echo/security/advisories/GHSA-cxf3-9h37-7rr8
  - https://sploitus.com/exploit?id=CVE-2026-118264&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Labstack Echo to v4.16.1 or v5.4.1 across all deployed applications
      owner: IT Operations
      due: 24h
      evidence: Vendor advisory confirms these versions contain the fix for the raw proxy validation issue.
  hunt_leads:
    - lead: Identify high-volume or unusual WebSocket upgrade traffic followed by non-WebSocket HTTP request patterns on the same connection
      technique_id: T1190
      data_needed:
        - Web server access logs
        - Application proxy logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Exploitation relies on an upstream rejecting an upgrade but maintaining the connection, which may result in observable log anomalies.
  mitigation_plan:
    - priority: immediate
      action: Enforce independent authorization on upstream services and block unauthorized WebSocket upgrade attempts at the proxy edge
      owner: Security Engineering
      addresses: Route-level authentication bypass
      evidence: The advisory notes these as valid workarounds to prevent raw tunnel abuse.
updates:
  - at: "2026-10-28T23:36:57Z"
    level: L2
    summary: poc_available; added CVE-2026-118264
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-118264&utm_source=rss&utm_medium=rss
---

The Proxy middleware in Labstack Echo (v4 and v5) fails to validate if an upstream server successfully upgrades to a WebSocket connection. When an upstream server rejects a WebSocket upgrade request but keeps the underlying TCP connection open, Echo incorrectly maintains a raw tunnel. This state causes subsequent HTTP requests on that same connection to be forwarded directly to the upstream service, bypassing any Echo-level router logic or middleware (e.g., authentication, authorization).

## Attack Chain
1. Attacker identifies a proxy route in an Echo-based application.
2. Attacker sends a WebSocket upgrade request (HTTP GET with Connection: Upgrade, Upgrade: websocket) to the proxy route.
3. The target upstream service receives the request, determines it cannot upgrade, and returns a standard HTTP response (e.g., 400 or 403) while keeping the connection alive.
4. Echo's Proxy middleware erroneously promotes the connection to a raw tunnel upon receiving the upgrade initiation, failing to confirm the upstream's non-101 response status.
5. Attacker sends subsequent unauthorized HTTP requests over the existing, now-tunneling connection.
6. The proxy forwards these requests directly to the upstream, bypassing route-level controls implemented in the Echo layer.

## Impact
Unauthorized access to upstream resources that rely on Echo-level authentication or authorization. The bypass does not provide arbitrary-host proxying and relies on existing upstream reachability.

## Recommendation
- Upgrade Echo to v4.16.1 or v5.4.1 immediately to implement upstream response validation.
- If immediate patching is not possible, enforce independent authentication and authorization checks at the upstream resource level.
- Implement request filtering at the perimeter or load balancer to block WebSocket upgrade requests if they are not explicitly required for specific routes.
