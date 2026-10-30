---
brief_id: brief-2026-10-30-oauthlib-device-code-bypass
event_id: brief-2026-10-30-oauthlib-device-code-bypass
revision: 1
activity_at: "2026-10-30T09:04:51Z"
title: 'OAuthLib: Improper device code validation in device flow (CVE-2026-49272)'
slug: 2026-10-oauthlib-device-code-bypass
description: OAuthLib fails to validate the device_code parameter during device flow token requests, allowing attackers with a valid client ID to illicitly obtain bearer tokens.
date: "2026-10-30T09:04:51Z"
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
cves:
  - id: CVE-2026-49272
    kev_status: unknown
references:
  - https://github.com/advisories/GHSA-3jp2-3mrg-2vxc
  - https://datatracker.ietf.org/doc/html/rfc8628#section-3.4
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Inventory applications using OAuthLib for device flow workflows
      owner: SOC
      due: 48h
      evidence: 'Affected Packages: pip/oauthlib (vulnerable: >= 3.3.0, < 4.0.0)'
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
  mitigation_plan:
    - priority: immediate
      action: Upgrade to the latest version of oauthlib once released
      owner: IT Operations
      addresses: CVE-2026-49272
      evidence: 'Affected Packages: pip/oauthlib (vulnerable: >= 3.3.0, < 4.0.0)'
---

OAuthLib versions 3.3.0 through 3.x are affected by an authentication bypass vulnerability in the OAuth 2.0 Device Authorization Grant implementation (RFC 8628). Specifically, the `DeviceCodeGrant.validate_token_request` method fails to verify the `device_code` parameter. An attacker possessing a valid `client_id` that is configured for the device workflow can submit an OAuth token request with a fabricated or arbitrary `device_code` value to successfully receive a bearer token. This flaw bypasses the intended device authorization handshake.

## Impact

Successful exploitation allows unauthorized generation of bearer tokens for applications utilizing the affected OAuthLib version for device flow authentication, potentially leading to unauthorized access to protected resources.

## Recommendation

- Identify all internal services or products utilizing OAuthLib versions 3.3.0 through 3.x for OAuth 2.0 Device Authorization Grant workflows.
- Upgrade affected deployments to a patched version once available from the maintainers.
- If an immediate upgrade is not feasible, implement custom validation logic within the `RequestValidator` to manually verify the `device_code` before calling `DeviceCodeGrant.validate_token_request`.
- Audit OAuth server logs for token requests using `grant_type=urn:ietf:params:oauth:grant-type:device_code` that lack a corresponding successful device authorization initiation.
