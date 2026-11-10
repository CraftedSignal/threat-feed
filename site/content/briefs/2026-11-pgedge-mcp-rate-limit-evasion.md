---
brief_id: brief-2026-11-10-pgedge-mcp-rate-limit-evasion
event_id: brief-2026-11-10-pgedge-mcp-rate-limit-evasion
revision: 1
activity_at: "2026-11-10T18:59:43Z"
title: 'pgEdge Postgres MCP Server: Login rate limiting bypass (CVE-2026-125321)'
slug: 2026-11-pgedge-mcp-rate-limit-evasion
description: pgEdge Postgres MCP Server versions prior to 1.1.0 contain a vulnerability where an attacker can bypass login rate limiting by manipulating the X-Forwarded-For HTTP header.
date: "2026-11-10T18:59:43Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:pgedge:postgres_mcp:*:*:*:*:*:*:*:*
vendors:
  - pgEdge
products:
  - Postgres MCP Server (< 1.1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated login rate limiting evasion in pgEdge Postgres MCP Server via X-Forwarded-For.
    confidence_band: high
cves:
  - id: CVE-2026-125321
    cvss: 6.5
    kev_status: "false"
references:
  - https://github.com/pgEdge/pgedge-postgres-mcp/security/advisories/GHSA-v347-v3w7-7fq9
  - https://github.com/pgEdge/pgedge-postgres-mcp/issues/204
  - https://sploitus.com/exploit?id=CVELIST:CVE-2026-125321
  - https://sploitus.com/exploit?id=CVELIST:CVE-2026-125321&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade pgEdge Postgres MCP Server to 1.1.0 or later.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-125321 fixed in version 1.1.0.
  hunt_leads:
    - lead: Identify patterns of login failures or repeated requests where the X-Forwarded-For header contains unusual or rapidly rotating IP addresses.
      technique_id: T1190
      data_needed:
        - Web server access logs containing X-Forwarded-For headers.
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The flaw allows an unauthenticated caller to rotate addresses to evade throttling or assert another user address.
  mitigation_plan:
    - priority: immediate
      action: Ensure proxy configurations replace the X-Forwarded-For header to prevent header injection.
      owner: IT Operations
      addresses: CVE-2026-125321
      evidence: The published nginx configuration appended rather than replaced X-Forwarded-For, making the issue reachable.
---

pgEdge Postgres MCP Server versions prior to 1.1.0 contain a vulnerability (CVE-2026-125321) in the login rate limiting mechanism. The implementation relies on the leftmost value of the caller-supplied 'X-Forwarded-For' header to identify the client IP address. An attacker can manipulate this header to rotate perceived IP addresses, thereby evading rate limiting or exhausting the rate limit bucket of other users. This issue is reachable when the HTTP transport is enabled, especially if the deployment configuration appends rather than replaces the 'X-Forwarded-For' header.

## Impact

Successful exploitation allows unauthenticated attackers to bypass login rate limits, facilitating brute-force or credential stuffing attacks against the Postgres MCP server.

## Recommendation

- Upgrade pgEdge Postgres MCP Server to version 1.1.0 or later immediately.
- Review ingress and proxy configurations to ensure that 'X-Forwarded-For' headers are sanitized and correctly replaced by trusted upstream proxies before reaching the application.
- Audit logs for repeated login failures originating from diverse or suspicious 'X-Forwarded-For' header values.
