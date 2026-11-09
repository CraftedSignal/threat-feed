---
brief_id: brief-2026-11-09-pocket-id-auth-bypass
event_id: brief-2026-11-09-pocket-id-auth-bypass
revision: 1
activity_at: "2026-11-09T22:14:31Z"
title: 'Pocket ID: Arbitrary audience injection in client credentials grant (CVE-2026-62662)'
slug: 2026-11-pocket-id-auth-bypass
description: Pocket ID contains an authentication bypass vulnerability where an authenticated OIDC client can supply an arbitrary resource parameter to obtain a signed access token for any audience, effectively bypassing service-to-service access controls.
date: "2026-11-09T22:14:31Z"
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
cpes:
  - cpe:2.3:a:pocket-id:pocket-id:*:*:*:*:*:*:*:*
vendors:
  - Pocket ID
products:
  - Pocket ID (< 0.0.0-20260622164202-8158452b3730)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Any authenticated OIDC client can obtain a Pocket ID-signed access token claiming authorization for any arbitrary audience.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1550.001
    technique_name: Application Access Token
    evidence: In deployments that do rely on the client credentials grant for service-to-service authorization, the isolation between services is entirely broken.
    confidence_band: high
cves:
  - id: CVE-2026-62662
    cvss: 7.7
    epss: 0.00266
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-q4xm-p75h-h9p3
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62662
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Pocket ID to version 0.0.0-20260622164202-8158452b3730 or higher.
      owner: IT Operations
      due: 24h
      evidence: Source states the vulnerability affects versions prior to 0.0.0-20260622164202-8158452b3730.
  hunt_leads:
    - lead: Analyze webserver access logs for token requests containing unexpected or non-standard "resource" parameter values in the POST body of /api/oidc/token requests.
      technique_id: T1550.001
      data_needed:
        - Webserver access logs (POST body / parameters)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The PoC demonstrates an attacker using a POST request with an arbitrary resource parameter to exploit the flaw.
  mitigation_plan:
    - priority: immediate
      action: Apply security patch by upgrading to version 0.0.0-20260622164202-8158452b3730.
      owner: IT Operations
      addresses: CVE-2026-62662
      evidence: The patch version is provided in the GHSA advisory.
---

Pocket ID is vulnerable to an authentication bypass via its OAuth 2.0 client credentials grant implementation. The application fails to validate the `resource` parameter provided during the token request in `backend/internal/service/oidc_service.go`. As a result, any authenticated client can request a token for any audience, including other registered service clients. The system lacks a registry of permitted audiences or authorization policies per client, allowing malicious clients to forge tokens that appear legitimate to downstream resource servers. This vulnerability is tracked as CVE-2026-62662.

## Attack Chain

1. Attacker acquires valid credentials for a registered OIDC client.
2. Attacker initiates an OAuth 2.0 `client_credentials` grant request to the Pocket ID token endpoint.
3. Attacker injects an arbitrary value into the `resource` field of the HTTP POST request.
4. Pocket ID validates the attacker's client credentials.
5. Pocket ID fails to validate the `resource` parameter against any allowlist or registered client metadata.
6. Pocket ID embeds the attacker-provided `resource` value into the `aud` (audience) claim of the generated JWT.
7. Attacker receives the signed token and uses it to authenticate against a target resource server.
8. Target resource server validates the token against Pocket ID's JWKS and incorrectly accepts the token due to the spoofed `aud` claim.

## Impact

Successful exploitation allows a compromised or malicious client to impersonate authorized service traffic, effectively breaking service-to-service isolation. The attacker can bypass audience-based access controls and gain unauthorized access to any resource server that relies on Pocket ID for token validation.

## Recommendation

1. Upgrade Pocket ID to version 0.0.0-20260622164202-8158452b3730 or later immediately to include mandatory resource validation.
2. Audit all existing OAuth clients for anomalous token requests to unexpected resource audiences.
3. Implement strict audience validation logic on all downstream resource servers to verify that the `aud` claim matches the specific resource identity, even if the token signature is valid.
