---
brief_id: brief-2026-11-04-wpo365-auth-bypass
event_id: brief-2026-11-04-wpo365-auth-bypass
revision: 2
activity_at: "2026-11-05T00:22:30Z"
revision_history:
  - revision: 2
    at: "2026-11-05T00:22:30Z"
    checksum: sha256:30c6879ec9866101d921351fc0a29afd500a185c5f03c1ff89cd2a6ae3047417
    summary: poc_available
    changed_fields:
      - claim_state
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-122220&utm_source=rss&utm_medium=rss
title: 'WPO365 | LOGIN: Authentication bypass via SAML replay (CVE-2026-122220)'
slug: 2026-11-wpo365-auth-bypass
description: The WPO365 | LOGIN plugin for WordPress fails to persist SAML message IDs, enabling attackers to perform replay attacks against the ACS endpoint to bypass authentication.
date: "2026-11-04T21:13:36Z"
lastmod: "2026-11-05T00:21:26Z"
type: advisory
claim_state: <nil>
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
cpes:
  - cpe:2.3:a:wpo365:login:*:*:*:*:*:wordpress:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-122220&utm_source=rss&utm_medium=rss
vendors:
  - WPO365
products:
  - WPO365 | LOGIN (< 45.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: Attackers who capture a validly-signed SAMLResponse can replay it to the ACS endpoint repeatedly within its assertion validity window to log in as the victim.
    confidence_band: high
cves:
  - id: CVE-2026-122220
    cvss: 7.4
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-122220
  - https://sploitus.com/exploit?id=CVE-2026-122220&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Patch WPO365 | LOGIN to version 45.2 or later.
      owner: IT Operations
      due: 24h
      evidence: Plugin before version 45.2 contains an authentication bypass
  hunt_leads:
    - lead: Identify repeated SAML assertion processing for the same user sessions in web server logs.
      technique_id: T1550
      data_needed:
        - Web server access logs containing HTTP POST requests to the plugin ACS endpoint
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attackers who capture a validly-signed SAMLResponse can replay it to the ACS endpoint repeatedly
updates:
  - at: "2026-11-05T00:21:26Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-122220&utm_source=rss&utm_medium=rss
---

The WPO365 | LOGIN plugin for WordPress contains an authentication bypass vulnerability (CVE-2026-122220) due to a logic error in the `Saml2_Service::check_message_id()` function. The function fails to persist processed SAML message IDs to the `wpo365_saml_message_ids` transient cache because the code returns prematurely. As a result, the plugin cannot effectively enforce anti-replay checks for SAML assertions. 

## Impact
An unauthenticated attacker who successfully captures a validly-signed SAML response can replay that assertion against the plugin ACS endpoint. This allows for unauthorized access to the application as the authenticated user, including users with administrative privileges, until the assertion validity window expires.

## Recommendation
- Update the WPO365 | LOGIN plugin to version 45.2 or later immediately to resolve the persistence logic error in the SAML response validator.
- Audit existing SAML configurations to ensure that the IdP and SP are strictly enforcing assertion lifetimes to minimize the window of opportunity for potential replay attacks.
