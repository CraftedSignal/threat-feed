---
brief_id: brief-2026-10-24-crushftp-auth-bypass
event_id: brief-2026-10-24-crushftp-auth-bypass
revision: 2
activity_at: "2026-10-29T19:50:13Z"
revision_history:
  - revision: 2
    at: "2026-10-29T19:50:13Z"
    checksum: sha256:bc574799149f3f71e27f611e460261cfcfcd3b55688862c26b81de30737c0dd4
    summary: new product
    changed_fields:
      - affected_products
      - claim_state
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4211
title: 'CrushFTP: Authentication bypass and administrative account creation (CVE-2025-54309)'
slug: 2026-10-crushftp-auth-bypass
description: CVE-2025-54309 is an authentication bypass vulnerability in CrushFTP allowing unauthenticated administrative account creation via manipulation of the AS2-To header.
date: "2026-10-24T00:02:44Z"
lastmod: "2026-10-29T19:48:24Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Needs environment validation
cpes:
  - cpe:2.3:a:crushftp:crushftp:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - web-exploitation
  - crushftp
vendors:
  - CrushFTP
products:
  - CrushFTP (10.x < 10.8.5, 11.x < 11.3.4_23)
  - CrushFTP (< 10.8.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: CVE-2025-54309 is an authentication bypass vulnerability in CrushFTP that allows unauthorized administrative user creation
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136.002
    technique_name: Domain Account
    evidence: Attackers can send a crafted POST request... enabling the creation of unauthorized administrative accounts
    confidence_band: high
cves:
  - id: CVE-2025-54309
    cvss: 9
    epss: 0.93473
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-BLUEISBEAUTIFUL-CVE-2025-54309
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-BLUEISBEAUTIFUL-CVE-2025-54309&utm_source=rss&utm_medium=rss
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4211
rules:
  - title: Detect CVE-2025-54309 Exploitation - Unauthorized Admin User Creation via AS2 Header
    description: Detects exploitation attempts against CVE-2025-54309 by monitoring for POST requests to the WebInterface function endpoint with the setUserItem command, which is used to create administrative users.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1136.002
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all CrushFTP installations and verify version against 10.8.5 and 11.3.4_23
      owner: IT Operations
      due: 24h
      evidence: Source identifies vulnerability in versions below 10.8.5 and 11.3.4_23
  hunt_leads:
    - lead: Search logs for unauthorized account creation activity matching 'setUserItem' command
      technique_id: T1136.002
      data_needed:
        - Application/Web server logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploitation involves invoking the 'setUserItem' command
  mitigation_plan:
    - priority: immediate
      action: Upgrade CrushFTP to 10.8.5 or 11.3.4_23
      owner: IT Operations
      addresses: CVE-2025-54309
      evidence: Source provides these versions as the fix
updates:
  - at: "2026-10-29T19:48:24Z"
    level: L1
    summary: new product
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4211
---

CVE-2025-54309 is an authentication bypass vulnerability in CrushFTP, specifically within the `loginCheckHeaderAuth()` method of `crushftp/server/ServerSessionHTTP.java`. The vulnerability arises from improper validation logic when processing the 'AS2-To' header. Attackers can bypass authentication by sending a crafted request to the `/WebInterface/function/` endpoint, enabling them to execute administrative actions, such as creating new unauthorized administrative accounts.

## Attack Chain

1. Attacker sends a POST request to the `/WebInterface/function/` endpoint of a target CrushFTP server.
2. Attacker includes a crafted 'AS2-To' header (left empty or containing specific patterns) to trigger the flawed validation logic.
3. The server executes `loginCheckHeaderAuth()`, which evaluates the 'AS2-To' header.
4. The logic fails to enforce authentication due to a missing delimiter (the '-_-') in the 'AS2-To' header.
5. The server process grants the request context, bypassing authentication checks.
6. The attacker invokes the 'setUserItem' command within the request body.
7. The system creates a new administrative user account.

## Impact

Successful exploitation allows unauthenticated attackers to gain administrative access to the CrushFTP server, potentially leading to full system compromise, data theft, and persistence through the creation of unauthorized admin accounts.

## Recommendation

1. Patch immediately: Upgrade all instances of CrushFTP to version 10.8.5 or higher (for the 10.x branch) or 11.3.4_23 or higher (for the 11.x branch).
2. Monitor web access: Audit access logs for requests to `/WebInterface/function/` containing unusual 'AS2-To' headers or calls to the `setUserItem` function.
3. Incident Response: Review existing administrative user accounts for unauthorized additions created recently.
