---
title: Authentication Bypass in Grav Login OAuth Plugin
slug: 2026-10-grav-oauth-auth-bypass
description: Grav Login OAuth plugin before 1.4.3 is vulnerable to account takeover due to the use of deterministic, predictable credentials generated from provider identifiers.
date: "2026-10-12T18:31:32Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:getgrav:grav-plugin-login-oauth:*:*:*:*:*:*:*:*
vendors:
  - Grav
products:
  - grav-plugin-login-oauth (< 1.4.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1133
    technique_name: External Remote Services
    evidence: Unauthenticated remote attackers who learn or guess a provider identifier can reproduce these credentials and log in, gaining administrative control of privileged accounts.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1133
    technique_name: External Remote Services
    evidence: Unauthenticated remote attackers who learn or guess a provider identifier can reproduce these credentials and log in, gaining administrative control of privileged accounts.
    confidence_band: high
cves:
  - id: CVE-2026-109321
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109321
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade grav-plugin-login-oauth to version 1.4.3 or later.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-109321 remediation requires plugin update.
  mitigation_plan:
    - priority: immediate
      action: Upgrade grav-plugin-login-oauth to 1.4.3 or later.
      owner: IT Operations
      addresses: CVE-2026-109321
      evidence: NVD advisory indicates vulnerability is resolved in 1.4.3.
---

The Grav Login OAuth plugin (grav-plugin-login-oauth) versions prior to 1.4.3 contain a critical authentication bypass vulnerability. During the account provisioning process for OAuth-authenticated users, the plugin generates account credentials using predictable patterns. Specifically, it assigns a username based on the format 'provider.id' and sets the user password to an unsalted MD5 hash of the provider identifier. 

Critically, the plugin fails to disable the standard password-based login mechanism for these provisioned accounts. Consequently, an unauthenticated remote attacker who identifies the provider identifier - which may be discoverable through system reconnaissance or public interaction - can compute the valid MD5 password hash. This allows the attacker to authenticate as the victim user. If an administrative account is targeted by this process, the attacker can successfully escalate their privileges to full site administrator, leading to complete compromise of the Grav installation.

## Impact

Successful exploitation allows unauthenticated remote attackers to gain unauthorized access to any user account provisioned via the OAuth plugin. If an administrator account is affected, the attacker gains full control of the Grav CMS instance, which can be leveraged for data exfiltration, site defacement, or persistent backdooring.

## Recommendation

* Immediately upgrade the Grav Login OAuth plugin to version 1.4.3 or later to remediate CVE-2026-109321.
* Audit existing users within the Grav administrative console for any accounts provisioned via OAuth that have unexpectedly enabled local password authentication.
* Review web server access logs for anomalous authentication attempts to the Grav login endpoint, specifically looking for repeated successful logins originating from non-standard IP addresses for known administrative or high-privilege users.
