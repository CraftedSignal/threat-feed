---
brief_id: brief-2026-10-30-oauthlib-device-code-bypass
event_id: brief-2026-10-30-oauthlib-device-code-bypass
revision: 2
activity_at: "2026-10-31T03:22:28Z"
revision_history:
  - revision: 2
    at: "2026-10-31T03:22:28Z"
    checksum: sha256:7915d30b7153280e4e3c774a5ed7e3161f6a1a8a7e8ea0aed8fec438fa007ec0
    summary: added coverage for oauthlib (< 4.0.0)
    changed_fields:
      - action_plan
      - affected_products
      - cves
      - lastmod
      - references
      - ttps
      - updates
    source_urls:
      - https://github.com/advisories/GHSA-7984-qgvg-3j9c
title: 'OAuthLib: Improper device code validation in device flow (CVE-2026-49272)'
slug: 2026-10-oauthlib-device-code-bypass
description: OAuthLib fails to validate the device_code parameter during device flow token requests, allowing attackers with a valid client ID to illicitly obtain bearer tokens.
date: "2026-10-30T09:04:51Z"
lastmod: "2026-10-31T03:20:56Z"
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
  validation_status: Source verified against GHSA-3jp2-3mrg-2vxc
cpes:
  - cpe:2.3:a:oauthlib_project:oauthlib:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - authentication-bypass
  - oauth
vendors:
  - OAuthLib
products:
  - oauthlib (>= 3.3.0, < 4.0.0)
  - oauthlib (< 4.0.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1550.001
    technique_name: Application Access Token
    evidence: An authenticated lower-privilege confidential client can obtain tokens authorized under another client's grant and scope policy.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The affected public surface is the OAuth2 token endpoint handling for client_credentials and password grants.
    confidence_band: high
cves:
  - id: CVE-2026-49272
    kev_status: unknown
  - id: CVE-2026-118669
    kev_status: unknown
references:
  - https://github.com/advisories/GHSA-3jp2-3mrg-2vxc
  - https://datatracker.ietf.org/doc/html/rfc8628#section-3.4
  - https://github.com/advisories/GHSA-7984-qgvg-3j9c
  - https://github.com/oauthlib/oauthlib/blob/b3f9edffed6b370e3eb92721cea0da22ec7e18b9/oauthlib/oauth2/rfc6749/grant_types/client_credentials.py#L106-L119
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Inventory applications using OAuthLib for device flow workflows
      owner: SOC
      due: 48h
      evidence: 'Affected Packages: pip/oauthlib (vulnerable: >= 3.3.0, < 4.0.0)'
    - action: Upgrade oauthlib to 4.0.0 or later on all OAuth provider services.
      owner: IT Operations
      due: 48h
      evidence: Source advisory recommends version 4.0.0 as the fix.
  hunt_leads:
    - lead: Identify abnormal frequency or suspicious source IPs making token requests using the device code grant type
      technique_id: T1190
      data_needed:
        - OAuth token endpoint logs
        - HTTP Request parameters
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Call to the token endpoint with a grant type of "urn:ietf:params:oauth:grant-type:device_code" and a bogus device_code is able to get a bearer token
    - lead: Identify suspicious token requests where the provided client_id in the body differs from the authenticated client_id context.
      technique_id: T1550.001
      data_needed:
        - Application logs containing authenticated client ID and requested client_id parameter from POST body.
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability stems from the identity split between request.client.client_id and request.client_id during validation.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to the latest version of oauthlib once released
      owner: IT Operations
      addresses: CVE-2026-49272
      evidence: 'Affected Packages: pip/oauthlib (vulnerable: >= 3.3.0, < 4.0.0)'
    - priority: immediate
      action: Upgrade oauthlib to version 4.0.0+.
      owner: IT Operations
      addresses: CVE-2026-118669
      evidence: Vulnerable to < 4.0.0.
updates:
  - at: "2026-10-31T03:20:56Z"
    level: L2
    summary: added coverage for oauthlib (< 4.0.0)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-7984-qgvg-3j9c
---

OAuthLib versions 3.3.0 through 3.x are affected by an authentication bypass vulnerability in the OAuth 2.0 Device Authorization Grant implementation (RFC 8628). Specifically, the `DeviceCodeGrant.validate_token_request` method fails to verify the `device_code` parameter. An attacker possessing a valid `client_id` that is configured for the device workflow can submit an OAuth token request with a fabricated or arbitrary `device_code` value to successfully receive a bearer token. This flaw bypasses the intended device authorization handshake.

## Impact

Successful exploitation allows unauthorized generation of bearer tokens for applications utilizing the affected OAuthLib version for device flow authentication, potentially leading to unauthorized access to protected resources.

## Recommendation

- Identify all internal services or products utilizing OAuthLib versions 3.3.0 through 3.x for OAuth 2.0 Device Authorization Grant workflows.
- Upgrade affected deployments to a patched version once available from the maintainers.
- If an immediate upgrade is not feasible, implement custom validation logic within the `RequestValidator` to manually verify the `device_code` before calling `DeviceCodeGrant.validate_token_request`.
- Audit OAuth server logs for token requests using `grant_type=urn:ietf:params:oauth:grant-type:device_code` that lack a corresponding successful device authorization initiation.
