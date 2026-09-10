---
title: Authentication Bypass Vulnerability in SSSD IdP Provider
slug: 2026-09-sssd-auth-bypass
description: A vulnerability in the SSSD IdP authentication provider allows an attacker to impersonate a target user if their IdP identifier is a prefix of the victim's identifier.
date: "2026-09-10T03:03:44Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:sssd:sssd:*:*:*:*:*:*:*:*
vendors:
  - SSSD
products:
  - System Security Services Daemon
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: An attacker whose IdP identifier is a strict prefix of a target user's identifier can authenticate as the target user.
    confidence_band: high
cves:
  - id: CVE-2026-87853
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-87853
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - IAM Team
  immediate_actions:
    - action: Monitor SSSD authentication logs for identifier collisions.
      owner: SOC
      due: 24h
      evidence: CVE-2026-87853 describes an authentication bypass via prefix matching.
  mitigation_plan:
    - priority: immediate
      action: Update SSSD packages as soon as patches become available.
      owner: IT Operations
      addresses: CVE-2026-87853
      evidence: NVD vulnerability disclosure.
---

A vulnerability exists within the System Security Services Daemon (SSSD) IdP authentication provider, specifically located in the `eval_access_token_buf()` function. The flaw stems from an improper implementation of identifier validation using `strncmp()`. Instead of performing an exact string comparison between the OIDC subject identifier and the authenticated user's identifier, the function performs a prefix comparison.

This logic error enables an attacker to gain unauthorized access to an account if their own IdP identifier matches the initial characters of a target user's identifier. For example, an attacker with an identifier of "user" could potentially authenticate as "username". This issue poses a significant risk to organizations relying on SSSD for federated authentication, as it effectively allows for identity spoofing without requiring knowledge of a password or secondary factors, provided the attacker can control or influence their own identifier within the configured IdP.
