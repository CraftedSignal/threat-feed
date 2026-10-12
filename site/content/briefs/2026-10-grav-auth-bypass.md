---
title: Authentication Bypass in Grav Login Plugin
slug: 2026-10-grav-auth-bypass
description: An authentication bypass vulnerability (CVE-2026-109312) in the Grav Login plugin allows attackers who possess a victim's password to disable two-factor authentication and hijack accounts by exploiting incomplete 2FA session validation.
date: "2026-10-12T18:34:54Z"
lastmod: "2026-10-12T18:35:04Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:getgrav:login:*:*:*:*:*:*:*:*
vendors:
  - Grav
products:
  - Login plugin (< 3.9.9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: Attackers with a victim's password can invoke update_user before completing 2FA to disable twofa_enabled and take over the account.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The publisher-controlled page rendered by Login::getPage() exposes the username and bearer token, enabling takeover of more privileged accounts.
    confidence_band: high
cves:
  - id: CVE-2026-109312
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109312
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109314
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Grav Login plugin to version 3.9.9 or later
      owner: IT Operations
      due: 24h
      evidence: NVD vulnerability disclosure
  hunt_leads:
    - lead: Anomalous POST requests to update_user endpoint
      technique_id: T1550
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source document identifies update_user as the exploitation vector
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Login plugin 3.9.9
      owner: IT Operations
      addresses: CVE-2026-109312
      evidence: CVE-2026-109312 remediation
updates:
  - at: "2026-10-12T18:35:04Z"
    level: L2
    summary: added coverage for Login plugin (< 3.9.9)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-109314
---

The Grav Login plugin versions 2.7.0 through 3.9.8 contain a critical authentication bypass vulnerability within the processUserProfile() function. The flaw stems from improper session state management, where the plugin verifies the existence of a session user but fails to ensure that a pending front-end two-factor authentication (2FA) session is fully authorized before processing updates. 

An attacker who has successfully obtained a victim's password can exploit this by interacting with the update_user method while a 2FA challenge is active. By bypassing the mandatory 2FA verification step, the attacker can programmatically disable twofa_enabled for the account. This effectively removes the second layer of security, granting the attacker full unauthorized access to the victim's account. This vulnerability poses a significant risk to administrative accounts if an attacker gains valid credentials, as it circumvents established multi-factor authentication controls.

## Impact

Successful exploitation results in full account takeover and the circumvention of two-factor authentication for the targeted Grav user. This impact is severe for administrative accounts, potentially allowing for site-wide configuration changes, unauthorized content injection, or complete platform compromise. The scope of targeting includes any Grav instance utilizing the Login plugin version 2.7.0 to 3.9.8.

## Recommendation

- Upgrade the Grav Login plugin to version 3.9.9 or later immediately to resolve the authentication logic flaw.
- Review web server access logs for anomalous POST requests to the update_user endpoint or unusual account profile modification patterns.
- Audit recent user account modifications, specifically looking for users who have had 2FA disabled unexpectedly or during anomalous access windows.
