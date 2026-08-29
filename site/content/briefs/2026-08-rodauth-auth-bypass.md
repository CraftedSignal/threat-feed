---
title: Authentication Bypass in Rodauth WebAuthn Login
slug: 2026-08-rodauth-auth-bypass
description: Rodauth versions prior to 2.46.0 contain an authentication bypass vulnerability in the webauthn_login route, allowing attackers to impersonate arbitrary users via improper account resolution.
date: "2026-08-29T17:41:01Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:rodauth:rodauth:*:*:*:*:*:ruby:*:*
vendors:
  - Rodauth
products:
  - Rodauth (< 2.46.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: Attackers can exploit improper account resolution logic that falls back to session account identifiers instead of validating the credential binding to complete authentication as arbitrary users.
    confidence_band: high
cves:
  - id: CVE-2026-82466
    cvss: 8.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82466
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Rodauth to version 2.46.0
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-82466 requires version 2.46.0 for remediation.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Rodauth to 2.46.0 or later
      owner: IT Operations
      addresses: CVE-2026-82466
      evidence: NVD vulnerability disclosure
---

Rodauth, an authentication framework for Ruby applications, contains a critical authentication bypass vulnerability (CVE-2026-82466) in the webauthn_login route. The flaw affects all versions prior to 2.46.0. An attacker who is already authenticated as a low-privileged user can exploit this vulnerability to impersonate any other account within the application.

The issue arises from flawed account resolution logic within the WebAuthn authentication flow. Instead of enforcing a strict binding between the provided WebAuthn credential and the intended target account, the application incorrectly falls back to session-based identifiers. This behavior allows an attacker to complete the authentication process for a different user without possessing their valid credentials. This vulnerability poses a significant risk to the integrity and confidentiality of user accounts in applications relying on Rodauth for WebAuthn-based authentication.

## Impact

Successful exploitation allows for full account takeover, enabling unauthorized access to any user profile, associated private data, and administrative functions. The scope of impact is limited to applications utilizing the Rodauth framework with the webauthn_login route enabled.

## Recommendation

- Upgrade the Rodauth framework to version 2.46.0 or later to apply the security patch for CVE-2026-82466.
- Review application access logs for an unusual frequency of WebAuthn authentication successes by users that do not correlate with expected session activity.
- Audit custom authentication logic that integrates with Rodauth to ensure credential binding is strictly validated server-side.
