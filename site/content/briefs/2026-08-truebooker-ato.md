---
title: Account Takeover in TrueBooker WordPress Plugin via Unauthenticated AJAX
slug: 2026-08-truebooker-ato
description: The TrueBooker WordPress plugin contains an unauthenticated account takeover vulnerability (CVE-2026-16142) allowing attackers to modify arbitrary user email addresses and facilitate account hijacking.
date: "2026-08-15T10:17:59Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - WordPress
products:
  - TrueBooker (<= 1.2.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to change any WordPress user account email address.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078.002
    technique_name: 'Valid Accounts: Domain Accounts'
    evidence: An attacker can then use the native WordPress password reset flow... and take over the account.
    confidence_band: high
cves:
  - id: CVE-2026-16142
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16142
rules:
  - title: Detects CVE-2026-16142 Exploitation - Unauthenticated Email Modification
    description: Detects potential exploitation of CVE-2026-16142 by identifying unauthenticated AJAX requests to the TrueBooker update handler.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Update TrueBooker plugin to latest version
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-16142 mitigation requires patching the vulnerable version.
  mitigation_plan:
    - priority: immediate
      action: Disable TrueBooker plugin if update not possible
      owner: IT Operations
      addresses: CVE-2026-16142
      evidence: Source confirms vulnerability in versions <= 1.2.6.
---

The TrueBooker plugin for WordPress (versions 1.2.6 and earlier) is susceptible to an unauthenticated account takeover vulnerability, designated as CVE-2026-16142. The flaw exists within the 'add_front_user_update()' AJAX handler, which fails to verify the authentication status or the ownership of the account being modified. Because the handler trusts user-supplied input for the 'truebooker_wp_user_id' parameter and passes it directly to the 'wp_update_user()' function, unauthenticated attackers can overwrite the email address associated with any user account, including administrative accounts. By redirecting a target account's email to an attacker-controlled address, the threat actor can leverage the native WordPress password reset functionality to seize control of the account. This vulnerability poses a severe risk to WordPress installations utilizing this plugin.

## Attack Chain

1. Attacker identifies a WordPress installation running the vulnerable TrueBooker plugin version 1.2.6 or earlier.
2. Attacker crafts a malicious AJAX request targeting the 'add_front_user_update()' action.
3. Attacker specifies the 'truebooker_wp_user_id' parameter corresponding to the target administrator account ID.
4. Attacker provides an arbitrary, attacker-controlled email address in the request parameters.
5. The vulnerable plugin accepts the request without authentication checks and executes 'wp_update_user()' using the provided inputs.
6. The target administrator's email address is successfully updated in the WordPress database to the attacker's email address.
7. Attacker initiates a standard password reset request for the target account via the legitimate WordPress '/wp-login.php?action=lostpassword' endpoint.
8. Attacker intercepts the reset token delivered to their controlled email and completes the password reset, successfully achieving full account takeover.

## Impact

Successful exploitation allows unauthenticated attackers to gain full administrative control over the affected WordPress site. This leads to complete data exfiltration, defacement, the potential for further server-side command execution via administrative privileges, and the compromise of all user data stored within the application.

## Recommendation

Prioritize the update of the TrueBooker plugin to the latest patched version. If updates are unavailable, disable the plugin immediately. Monitor web server logs for suspicious POST requests to 'admin-ajax.php' containing the 'truebooker_wp_user_id' parameter.
