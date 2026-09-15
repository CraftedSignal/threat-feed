---
title: ZITADEL Privilege Escalation via OAuth2 Token Exchange
slug: 2026-09-zitadel-auth-bypass
description: A vulnerability in ZITADEL's OAuth2 Token Exchange endpoint (CVE-2026-56668) allows authenticated users to exchange low-privilege tokens for highly privileged tokens by bypassing authorization and scope validation checks.
date: "2026-09-15T07:04:14Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:zitadel:zitadel:*:*:*:*:*:*:*:*
tags:
  - auth-bypass
  - privilege-escalation
  - oauth2
vendors:
  - ZITADEL
products:
  - ZITADEL (3.0.0 through 3.4.12)
  - ZITADEL (4.0.0 through 4.15.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1185
    technique_name: Browser Session Hijacking
    evidence: An authenticated user or client to exchange a low-privilege access token for a token with elevated permissions at a completely different application.
    confidence_band: high
cves:
  - id: CVE-2026-56668
    cvss: 8.1
    epss: 0.00413
references:
  - https://github.com/advisories/GHSA-vrh8-c9cm-wh8v
  - https://github.com/zitadel/zitadel/releases/tag/v4.15.3
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56668
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade ZITADEL to version 4.15.3 or later
      owner: IT Operations
      due: 24h
      evidence: Source states patch resolves issue by enforcing scope and audience verification
  mitigation_plan:
    - priority: immediate
      action: Set ZITADEL_DEFAULTINSTANCE_FEATURES_TOKENEXCHANGE=false or remove Token Exchange grant type from clients
      owner: Security Engineering
      addresses: CVE-2026-56668
      evidence: Source documentation on workarounds
---

ZITADEL is vulnerable to an authorization flaw in its OAuth2 Token Exchange (RFC 8693) implementation, specifically within the `urn:ietf:params:oauth:grant-type:token-exchange` flow. The vulnerability (CVE-2026-56668) allows an authenticated user or client to exchange an existing low-privilege access token for a new token associated with a different, highly-privileged application.

This occurs because the ZITADEL platform fails to verify if the subject of the incoming token is authorized to request the target audience or client. Furthermore, the system fails to enforce that the newly requested scopes are a subset of the original token's authorized scopes. An attacker can leverage this to acquire unauthorized project roles or access sensitive profile data across administrative boundaries. The risk is significantly amplified when public clients are involved, as they do not require client secrets to initiate the exchange. This vulnerability affects ZITADEL 3.x and 4.x versions prior to 4.15.3.

## Impact

Successful exploitation allows attackers to escalate privileges from a low-privilege user to an administrative role within target projects or applications. This can lead to unauthorized data access, exfiltration of sensitive profile information, and complete control over secondary applications relying on ZITADEL for identity management. The vulnerability impacts all ZITADEL instances that allow OAuth2 Token Exchange, posing a critical risk to multi-tenant or project-based infrastructure where application-level isolation is enforced via ZITADEL.

## Recommendation

1. Upgrade ZITADEL immediately to version 4.15.3 or later to resolve CVE-2026-56668.
2. If patching is delayed, disable the Token Exchange functionality by setting `ZITADEL_DEFAULTINSTANCE_FEATURES_TOKENEXCHANGE=false` via environment variables.
3. Alternatively, audit and remove the `urn:ietf:params:oauth:grant-type:token-exchange` grant type from all high-privilege or public client configurations within the ZITADEL console.
4. Review ZITADEL audit logs for anomalous token exchange requests where the requested client or scope appears inconsistent with the original token's assigned project context.
