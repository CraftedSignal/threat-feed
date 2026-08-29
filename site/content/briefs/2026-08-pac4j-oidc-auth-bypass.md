---
title: Authentication Bypass in pac4j-oidc via Token Forgery
slug: 2026-08-pac4j-oidc-auth-bypass
description: An authorization bypass vulnerability in pac4j-oidc versions prior to 6.5.6 allows attackers to forge OIDC access tokens by exploiting the library's failure to validate token signatures, issuers, audiences, and expiration.
date: "2026-08-29T17:40:49Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:pac4j:pac4j-oidc:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - authentication-bypass
  - oidc
  - identity-security
vendors:
  - pac4j
products:
  - pac4j-oidc (< 6.5.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can forge access tokens with administrative roles paired with valid ID tokens to bypass authorization checks.
    confidence_band: high
cves:
  - id: CVE-2026-82461
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82461
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade pac4j-oidc to version 6.5.6 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-82461 advisory specifies fix in 6.5.6
  mitigation_plan:
    - priority: immediate
      action: Upgrade pac4j-oidc to 6.5.6 or later
      owner: Application Security
      addresses: CVE-2026-82461
      evidence: Source explicitly names version 6.5.6 as the fixed release
---

The pac4j-oidc library, specifically versions prior to 6.5.6, contains a critical vulnerability (CVE-2026-82461) in its OpenID Connect (OIDC) implementation regarding token validation. The library fails to perform mandatory security checks on access tokens, specifically omitting the verification of cryptographic signatures, token issuers, intended audiences, and expiration timestamps. This oversight occurs specifically during the extraction of Keycloak realm and client roles. By manipulating these parameters, an attacker can craft forged access tokens containing arbitrary administrative roles. When paired with a legitimate ID token, these forged tokens permit attackers to circumvent authorization controls in any downstream application relying on pac4j-oidc for role-based access control. This flaw poses a high risk to identity-reliant architectures, as it effectively renders authentication mechanisms toothless by allowing privilege escalation via token impersonation.

## Impact

Successful exploitation allows for full unauthorized access and privilege escalation within applications utilizing the affected library. This allows an attacker to operate with administrative rights without valid authentication, potentially exposing sensitive data or allowing full application takeover. All sectors deploying applications that use the pac4j-oidc library with Keycloak integration are potentially impacted.

## Recommendation

* Immediately update the pac4j-oidc library to version 6.5.6 or higher to ensure proper OIDC token validation is enforced.
* Audit application logs for anomalous role assignments or identity claims that do not correspond to established user provisioning patterns.
* Review all downstream services relying on pac4j-oidc for authorization to ensure that they are not accepting forged tokens due to the identified validation logic flaw.
