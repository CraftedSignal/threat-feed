---
brief_id: brief-2026-10-27-better-auth-oauth-magic-link-bypass
event_id: brief-2026-10-27-better-auth-oauth-magic-link-bypass
revision: 2
activity_at: "2026-10-27T17:58:45Z"
revision_history:
  - revision: 2
    at: "2026-10-27T17:58:45Z"
    checksum: sha256:2cd4d04d549fb5706cd4e5a9dc4bda2383ebb8aab2796bd18ee27bb15436d229
    summary: added coverage for better-auth (>= 1.3.8-beta.3, < 1.7.0-rc.3)
    changed_fields:
      - action_plan
      - affected_products
      - lastmod
      - references
      - tags
      - ttps
      - updates
    source_urls:
      - https://github.com/advisories/GHSA-q84f-53jg-9ppm
title: 'Better Auth: OAuth state-to-Magic Link authentication bypass (CVE-2026-114607)'
slug: 2026-10-better-auth-oauth-magic-link-bypass
description: Better Auth is vulnerable to an authentication bypass where OAuth sign-in state can be used as a valid Magic Link token, allowing unauthenticated attackers to hijack user accounts or create unauthorized verified accounts.
date: "2026-10-27T17:53:49Z"
lastmod: "2026-10-27T17:58:10Z"
type: advisory
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
  validation_status: Source documentation verified
cpes:
  - cpe:2.3:a:better-auth:better-auth:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - web-vulnerability
  - cloud
  - account-takeover
  - authentication
  - oauth
  - phishing
  - session-hijacking
vendors:
  - better-auth
products:
  - better-auth (< 1.7.7)
  - better-auth (>= 1.3.8-beta.3, < 1.7.0-rc.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    subtechnique_id: T1566.002
    subtechnique_name: Spearphishing Link
    evidence: The attacker needs the opt-in device flow, a request the attacker creates, and a user who actively approves it.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: The attacker can then read or change any data the user's account can access.
    confidence_band: high
cves:
  - id: CVE-2026-114607
    cvss: 9.1
    epss: 0.0042
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-965c-763c-88jm
  - https://github.com/advisories/GHSA-q84f-53jg-9ppm
  - https://datatracker.ietf.org/doc/html/rfc8628
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
    - IT Operations
    - Development
  immediate_actions:
    - action: Inventory all applications using Better Auth versions 1.4.0-beta.18 through 1.7.6
      owner: SOC
      due: 24h
      evidence: Source identifies affected version range 1.4.0-beta.18 through before 1.7.7
    - action: Upgrade better-auth to 1.7.0 or later
      owner: Development
      due: 48h
      evidence: The fix first shipped in 1.7.0-rc.3.
    - action: Disable deviceAuthorization() plugin if immediate upgrade is not feasible
      owner: IT Operations
      due: 24h
      evidence: 'If you cannot upgrade yet, do the following: Disable deviceAuthorization().'
  hunt_leads:
    - lead: Identify suspicious Magic Link authentication requests where the token pattern matches expected OAuth state formats
      technique_id: T1190
      data_needed:
        - Application logs for /auth/magic-link and OAuth callback endpoints
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Attacker can use OAuth sign-in state value to finish a Magic Link sign-in
    - lead: Monitor application logs for frequent or anomalous calls to /device/code from unknown or suspicious client_id values
      technique_id: T1566.002
      data_needed:
        - Web server access logs
        - Application authentication logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: A device starts the flow by calling /device/code.
  mitigation_plan:
    - priority: immediate
      action: Set account.storeStateStrategy to 'cookie' or disable Magic Link/OAuth providers until 1.7.7 is available
      owner: IT Operations
      addresses: CVE-2026-114607
      evidence: Source provides workarounds including setting storeStateStrategy to cookie
    - priority: immediate
      action: Upgrade to better-auth 1.7.0
      owner: Development
      addresses: better-auth (>= 1.3.8-beta.3, < 1.7.0-rc.3)
      evidence: Upgrade to better-auth@1.7.0 or later.
updates:
  - at: "2026-10-27T17:58:10Z"
    level: L1
    summary: added coverage for better-auth (>= 1.3.8-beta.3, < 1.7.0-rc.3)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-q84f-53jg-9ppm
---

Better Auth versions 1.4.0-beta.18 through 1.7.6 are vulnerable to an authentication bypass (CVE-2026-114607). The library incorrectly allows an OAuth sign-in state value to be accepted as a valid Magic Link token. An attacker can initiate an OAuth flow for a specific target email address, obtain the resulting state identifier, and submit it to the Magic Link endpoint to complete authentication as that user. This vulnerability persists if specific configurations regarding `storeToken` and `storeIdentifier` strategies are in use.

## Attack Chain

1. Attacker initiates an OAuth sign-in flow through Better Auth for a target email address.
2. The application generates an OAuth state value to track this session.
3. The attacker intercepts or extracts the OAuth state value associated with the target email address.
4. The attacker submits the stolen OAuth state value to the Magic Link authentication endpoint.
5. Better Auth erroneously treats the OAuth state value as a valid Magic Link token.
6. The system grants the attacker a session associated with the target email address.

## Impact

Successful exploitation allows an unauthenticated attacker to gain full access to any existing user account if the email address is known, bypassing the need for mailbox access. If Magic Link sign-up is enabled for a non-existent email address, the attacker can create an account that the system incorrectly marks as email-verified, which can be leveraged to bypass secondary security controls or access gated application features.

## Recommendation

- Upgrade `better-auth` to version 1.7.7 or later as soon as it is released.
- Until the update is applied, prioritize switching `account.storeStateStrategy` to `"cookie"` if feasible, or disable the vulnerable combinations of Magic Link and social/Generic OAuth providers.
- Ensure all internal Better Auth plugins, adapters, and integrations are updated in synchronization with the core library to ensure consistent verification logic.
- Review and update custom `verification.storeIdentifier.overrides` to include the `magic-link:` and `auth-state:` prefixes as required by the upcoming security patch.
