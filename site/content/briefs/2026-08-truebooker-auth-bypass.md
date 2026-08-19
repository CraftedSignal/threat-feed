---
title: Unauthenticated Account Takeover in TrueBooker WordPress Plugin
slug: 2026-08-truebooker-auth-bypass
description: The TrueBooker plugin for WordPress up to version 1.2.6 is vulnerable to an unauthenticated account takeover via a flawed AJAX handler that allows attackers to modify user email addresses.
date: "2026-08-19T20:38:23Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - WordPress
products:
  - TrueBooker – Appointment Booking and Scheduler System (<= 1.2.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The TrueBooker plugin is vulnerable to Authorization Bypass Through User-Controlled Key leading to Account Takeover.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078.004
    technique_name: 'Valid Accounts: Cloud Accounts'
    evidence: This makes it possible for unauthenticated attackers to overwrite the email address of any WordPress user — including an administrator.
    confidence_band: high
cves:
  - id: CVE-2026-18315
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18315
rules:
  - title: Detect CVE-2026-18315 Exploitation - Unauthenticated AJAX Action
    description: Detects potential exploitation of the admin_user_create_cus AJAX handler in the TrueBooker plugin.
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
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch or disable TrueBooker plugin on all WordPress instances.
      owner: IT Operations
      due: 24h
      evidence: Plugin version 1.2.6 and below is confirmed vulnerable.
  hunt_leads:
    - lead: Search web logs for POST requests to admin-ajax.php containing the action admin_user_create_cus.
      technique_id: T1190
      data_needed:
        - webserver logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The vulnerability resides in the admin_user_create_cus AJAX handler.
  mitigation_plan:
    - priority: immediate
      action: Update TrueBooker plugin to the latest version.
      owner: IT Operations
      addresses: CVE-2026-18315
      evidence: NVD vulnerability report.
---

The TrueBooker - Appointment Booking and Scheduler System plugin for WordPress contains a critical authorization bypass vulnerability (CVE-2026-18315) affecting all versions up to and including 1.2.6. The vulnerability resides within the 'admin_user_create_cus' AJAX handler, which fails to perform necessary authentication or capability checks. 

Attackers can supply a 'truebooker_wp_user_id' parameter to the affected endpoint, which is then processed by 'wp_update_user' without verifying if the requestor has administrative privileges. By leveraging this, an unauthenticated actor can overwrite the email address associated with any user account in the WordPress database, including administrative accounts. Once the email address is updated to one controlled by the attacker, they can initiate the standard WordPress password reset process, intercept the recovery link, and gain full control over the compromised account. Defenders should identify any WordPress installations running this plugin and update to a patched version or disable the functionality immediately.

## Impact

The vulnerability results in a total account takeover for any user, including site administrators. Successful exploitation leads to full unauthorized access to the WordPress environment, enabling the attacker to modify site content, inject malicious scripts, redirect traffic, or exfiltrate sensitive data. Given that this plugin is used for scheduling, the compromise could also lead to the exposure of customer personal information and booking logs. There are no observed victim counts at this time, but the exploit is trivial to execute remotely.

## Recommendation

- Update the TrueBooker plugin to the latest version immediately to remediate the vulnerable AJAX handler.
- Audit WordPress user accounts for suspicious email address changes or recently created administrator accounts.
- Deploy the Sigma rule below to detect attempts to reach the vulnerable AJAX handler from external sources.
- Monitor web server logs for HTTP POST requests to 'admin-ajax.php' containing the 'admin_user_create_cus' action.
