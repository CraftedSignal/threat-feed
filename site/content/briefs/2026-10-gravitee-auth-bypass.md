---
title: Gravitee API Management Authentication Bypass via Default JWT Secret
slug: 2026-10-gravitee-auth-bypass
description: Gravitee API Management versions up to 4.12.22 allow unauthenticated remote attackers to forge JWTs using a default signing secret to impersonate any user, including administrators.
date: "2026-10-14T16:36:08Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:gravitee:gravitee_api_management:*:*:*:*:*:*:*:*
vendors:
  - Gravitee
products:
  - Gravitee API Management (<= 4.12.22)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: Remote, unauthenticated attackers can leverage this known default secret to sign arbitrary JSON Web Tokens (JWTs) to authenticate to the Management API.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1550.003
    technique_name: 'Use Alternate Authentication Material: Pass the Ticket'
    evidence: By supplying a valid user ID... within the subject claim... an attacker can successfully authenticate... impersonating administrators to gain full platform control.
    confidence_band: high
cves:
  - id: CVE-2020-37281
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2020-37281
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Gravitee API Management to the version addressing CVE-2020-37281.
      owner: IT Operations
      due: 24h
      evidence: Source advisory for CVE-2020-37281.
  mitigation_plan:
    - priority: immediate
      action: Rotate the 'jwt.secret' parameter to a cryptographically secure random string.
      owner: IT Operations
      addresses: CVE-2020-37281
      evidence: NVD vulnerability summary regarding default secret usage.
---

Gravitee API Management (APIM) versions through 4.12.22 contain a critical authentication bypass vulnerability stemming from the use of a hardcoded or default secret key used for HS256 JWT signing. Remote, unauthenticated attackers can leverage this known default secret to sign arbitrary JSON Web Tokens (JWTs). By supplying a valid user ID - such as an administrator account - within the subject ('sub') claim of the forged token, an attacker can successfully authenticate to the Management API. This bypass grants the attacker full control over the API management platform, including the ability to modify API configurations, view sensitive data, and manage underlying services. Defenders should verify that their deployments have moved away from default configuration secrets immediately, as this vulnerability requires no specialized knowledge beyond the publicly identified default value.

## Impact

Successful exploitation results in total compromise of the Gravitee API Management platform. An attacker with administrative access can exfiltrate sensitive data, manipulate API traffic, and potentially gain access to downstream systems connected through the gateway. Any organization utilizing default installation configurations for Gravitee APIM within the affected version range is at high risk of unauthorized administrative access.

## Recommendation

* Upgrade Gravitee API Management to the latest patched version immediately.
* Audit all production configurations to ensure that 'jwt.secret' values are cryptographically secure and rotated from any default values provided during installation.
* Review Management API access logs for anomalous Bearer token patterns, specifically looking for tokens that bypass standard identity provider handshakes.
* Implement strict firewall controls around the Management API to limit access to known, trusted administrative subnets.
