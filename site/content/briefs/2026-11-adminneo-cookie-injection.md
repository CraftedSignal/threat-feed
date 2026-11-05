---
brief_id: brief-2026-11-01-adminneo-cookie-injection
event_id: brief-2026-11-01-adminneo-cookie-injection
revision: 2
activity_at: "2026-11-05T01:20:05Z"
revision_history:
  - revision: 2
    at: "2026-11-05T01:20:05Z"
    checksum: sha256:f40693d6fc6e6c754893e7022972558fe28bad6480fe237f22db0f5fd6255ec7
    summary: added CVE-2026-96632
    changed_fields:
      - affected_products
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://github.com/advisories/GHSA-rx7m-wxwq-vxr9
title: 'AdminNeo: Cookie attribute injection via X-Forwarded-Prefix (CVE-2026-96631)'
slug: 2026-11-adminneo-cookie-injection
description: AdminNeo versions 4.6.0 through 5.5.0 contain a vulnerability where unsanitized X-Forwarded-Prefix headers allow cookie attribute injection, potentially leading to session hijacking and credential theft.
date: "2026-11-01T08:46:38Z"
lastmod: "2026-11-05T01:17:49Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source-documented vulnerability; requires environment verification of proxy configuration.
cpes:
  - cpe:2.3:a:adminneo:adminneo:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - cve
  - cookie-injection
vendors:
  - AdminNeo
products:
  - AdminNeo (>= 4.6.0, < 5.5.1)
  - AdminNeo (< 5.5.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker who can influence this header (e.g., through a reverse proxy that forwards it from clients, an attacker-controlled upstream proxy, or a man-in-the-middle position) can inject arbitrary cookie attributes.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The neo_key cookie contains the key used to encrypt/decrypt database passwords stored in the session. With this key, an attacker can decrypt saved database credentials.
    confidence_band: high
cves:
  - id: CVE-2026-96631
    kev_status: unknown
  - id: CVE-2026-96632
    kev_status: unknown
references:
  - https://github.com/advisories/GHSA-79wv-8rh2-9vp2
  - https://github.com/vrana/adminer/security/advisories/GHSA-c533-9qwm-8w5h
  - https://github.com/advisories/GHSA-rx7m-wxwq-vxr9
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory all internet-facing instances of AdminNeo version < 5.5.1.
      owner: IT Operations
      due: 24h
      evidence: Vulnerable version range specified in GHSA advisory.
  hunt_leads:
    - lead: Identify HTTP requests containing semicolons or multiple path attributes in the X-Forwarded-Prefix header.
      technique_id: T1190
      data_needed:
        - Web server access logs or WAF logs containing custom header fields.
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: PoC demonstrates using semicolons in X-Forwarded-Prefix to inject domain attributes.
  mitigation_plan:
    - priority: immediate
      action: Upgrade AdminNeo to version 5.5.1 or later.
      owner: IT Operations
      addresses: CVE-2026-96631
      evidence: Advisory confirms fix in 5.5.1.
updates:
  - at: "2026-11-05T01:17:49Z"
    level: L2
    summary: added CVE-2026-96632
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-rx7m-wxwq-vxr9
---

AdminNeo versions 4.6.0 through 5.5.0 are vulnerable to cookie attribute injection via the `X-Forwarded-Prefix` HTTP header. The application fails to sanitize this user-supplied header before concatenating it into the `REQUEST_URI` and subsequently using it to construct `Set-Cookie` response headers. An attacker can inject arbitrary cookie attributes, such as `Domain`, `Path`, and `SameSite`, which are then parsed and executed by the victim's browser. This flaw impacts the `neo_sid` (session ID) and `neo_key` (database password encryption key) cookies. 

This issue is tracked as CVE-2026-96631.

## Impact

Successful exploitation allows for session hijacking of the `neo_sid` cookie and potential theft of the `neo_key` cookie, which is used to encrypt database credentials. An attacker can force the browser to send these cookies to an attacker-controlled domain by injecting a `Domain` attribute (e.g., `Domain=.evil.com`).

## Recommendation

- Upgrade to AdminNeo version 5.5.1 or later immediately.
- If immediate patching is not possible, modify the reverse proxy configuration to strip the `X-Forwarded-Prefix` header from client requests or force it to a static, trusted value.
- Implement a WAF rule to block HTTP requests containing semicolons or other metacharacters in the `X-Forwarded-Prefix` header.
