---
brief_id: brief-2026-11-03-traq-oauth-bypass
event_id: brief-2026-11-03-traq-oauth-bypass
revision: 1
activity_at: "2026-11-03T20:04:43Z"
title: 'traQ: OAuth2 silent authorization bypass (CVE-2026-63198)'
slug: 2026-11-traq-oauth-bypass
description: The traQ messenger application prior to 3.28.3 fails to validate user consent during OAuth2 silent authorization requests, allowing unauthorized access to broader scopes.
date: "2026-11-03T20:04:43Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:traq_project:traq:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - oauth2
  - vulnerability
vendors:
  - Digital Creators Club traP
products:
  - traQ (< 3.28.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    subtechnique_id: T1550.001
    subtechnique_name: Application Access Token
    evidence: An attacker who controls an OAuth client capable of receiving authorization codes can target a user who previously consented to only some client scopes and obtain an access token containing broader registered scopes without additional consent.
    confidence_band: high
cves:
  - id: CVE-2026-63198
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63198
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade traQ to version 3.28.3
      owner: IT Operations
      due: 48h
      evidence: This issue is fixed in version 3.28.3.
  hunt_leads:
    - lead: Audit OAuth2 authorization logs for requests with 'prompt=none' and null/missing 'scope' parameters that resulted in success
      technique_id: T1550.001
      data_needed:
        - OAuth2 provider logs or web application access logs containing request parameters
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: When using the 'prompt=none' parameter with an empty or omitted scope, the application fails to properly validate existing consent.
  mitigation_plan:
    - priority: immediate
      action: Patch traQ instances to version 3.28.3
      owner: IT Operations
      addresses: CVE-2026-63198
      evidence: This issue is fixed in version 3.28.3.
---

The traQ messenger application (versions prior to 3.28.3) contains an authentication flaw in its OAuth2 implementation. When a silent authorization request (prompt=none) is made with an empty or omitted scope parameter, the application erroneously checks consent against an empty set, effectively bypassing existing restrictions. An attacker controlling an OAuth client can obtain an access token with broader registered scopes than what the user previously approved, provided the user had at least one prior consent entry for that client.

## Impact

Successful exploitation allows an attacker to escalate privileges within the application by obtaining access tokens with excessive permissions without further user interaction.

## Recommendation

- Upgrade the traQ messenger application to version 3.28.3 or later immediately.
- Review OAuth client registrations and audit application access tokens for unexpected scope assignments for users who have interacted with third-party or untrusted OAuth clients.
