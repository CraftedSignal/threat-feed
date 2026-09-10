---
title: Privilege Escalation Vulnerability in Bulk Password Reset WordPress Plugin
slug: 2026-09-wordpress-bulk-password-reset-vuln
description: The Bulk Password Reset WordPress plugin, versions 1.3.3 and earlier, contains a privilege escalation vulnerability allowing authenticated users to perform unauthorized account takeovers.
date: "2026-09-10T05:03:43Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:bulk_password_reset_project:bulk_password_reset:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - vulnerability
  - privilege-escalation
vendors:
  - WordPress
products:
  - Bulk Password Reset (<= 1.3.3)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The Bulk Password Reset plugin for WordPress is vulnerable to privilege escalation via account takeover in all versions up to, and including, 1.3.3.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: This makes it possible for authenticated attackers, with subscriber-level access and above, to change arbitrary user's email addresses.
    confidence_band: high
cves:
  - id: CVE-2026-14873
    cvss: 8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14873
action_plan:
  priority: elevated
  owners:
    - SOC
  immediate_actions:
    - action: Audit user profile updates for accounts with administrative roles.
      owner: SOC
      due: 24h
      evidence: Source document identifies account takeover via modification of user details.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Bulk Password Reset to the latest version or remove if a patch is unavailable.
      owner: IT Operations
      addresses: CVE-2026-14873
      evidence: Plugin version 1.3.3 and earlier are vulnerable.
---

The Bulk Password Reset plugin for WordPress (versions 1.3.3 and below) is susceptible to a privilege escalation vulnerability that allows authenticated attackers with subscriber-level access or higher to compromise administrative accounts. The security flaw stems from the plugin's failure to adequately validate user identities before processing administrative actions. Specifically, an attacker can modify sensitive user details, such as account email addresses, via the plugin's interface. By changing an administrator's email address to one controlled by the attacker, the malicious actor can leverage WordPress's native password reset functionality to regain access to the site as an administrator, ultimately resulting in full site takeover. This vulnerability is significant due to the low barrier to entry, as it only requires an existing subscriber-level account on the target WordPress installation.

## Attack Chain

1. Attacker registers or gains access to a subscriber-level account on the WordPress site.
2. Attacker authenticates to the WordPress dashboard using the subscriber account.
3. Attacker navigates to the Bulk Password Reset plugin interface.
4. Attacker leverages the plugin's lack of authorization checks to target an administrator account.
5. Attacker modifies the target administrator's profile, specifically changing the associated email address to an attacker-controlled address.
6. Attacker initiates a standard WordPress password reset request for the target administrator account.
7. Attacker receives the password reset link at the attacker-controlled email address.
8. Attacker resets the administrator password and authenticates as the administrator to gain full site control.

## Impact

Successful exploitation allows for complete site takeover by unauthorized users. Because the attack leverages native WordPress functionality after modifying profile data, the resulting administrative access is often difficult to distinguish from legitimate activity. This poses a critical risk to site integrity, data confidentiality, and overall availability for organizations relying on the affected plugin.

## Recommendation

1. Upgrade the Bulk Password Reset plugin to the latest version immediately, or disable and remove the plugin if a patched version is not yet available.
2. Audit all user accounts for suspicious email address changes, specifically looking for email addresses that do not match the expected corporate or organizational domain.
3. Review audit logs for unusual administrative logins occurring shortly after profile modification events.
4. Monitor web access logs for frequent or abnormal POST requests directed at the plugin's configuration or user management endpoints.
