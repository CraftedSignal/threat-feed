---
title: Authentication Bypass in miniOrange OTP Login Plugin
slug: 2026-10-miniorange-otp-bypass
description: An authentication bypass vulnerability in the miniOrange OTP Login, Verification and SMS Notifications plugin for WordPress allows unauthenticated attackers to hijack user sessions.
date: "2026-10-16T06:25:14Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:miniorange:otp_login_verification_and_sms_notifications:*:*:*:*:*:*:*:*
tags:
  - wordpress
  - plugin
  - authentication-bypass
  - cve-2026-103895
vendors:
  - miniOrange
products:
  - OTP Login, Verification and SMS Notifications (<= 5.5.8)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: The vulnerability allows attackers to inherit a legitimate user's Delay OTP grace window without ever supplying correct credentials.
    confidence_band: high
cves:
  - id: CVE-2026-103895
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103895
rules:
  - title: Detects CVE-2026-103895 - Potential Authentication Bypass in miniOrange Plugin
    description: Detects HTTP POST requests to the WordPress login page containing the mo_wp_login_intent parameter used to exploit the authentication bypass in the miniOrange OTP plugin.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1550.002
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch miniOrange OTP plugin to version 5.5.9 or higher.
      owner: IT Operations
      due: 24h
      evidence: Source advisory indicates the vulnerability is fixed in version 5.5.9.
  enrichment_needed:
    - item: CVE-2026-103895
      owner: CTI
      reason: Monitor for emerging exploit scripts or PoC code.
      evidence: New CVE disclosure.
  hunt_leads:
    - lead: Search web logs for POST requests containing mo_wp_login_intent=otp.
      technique_id: T1550.002
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The exploit requires the use of the mo_wp_login_intent=otp parameter.
  mitigation_plan:
    - priority: immediate
      action: Disable Delay OTP Verification feature in the plugin settings.
      owner: IT Operations
      addresses: CVE-2026-103895
      evidence: Exploitation requires Delay OTP Verification to be enabled.
---

The miniOrange OTP Login, Verification and SMS Notifications plugin for WordPress contains an authentication bypass vulnerability, assigned CVE-2026-103895, affecting all versions up to and including 5.5.8. The flaw resides in the `mo_by_pass_login()` function. The vulnerability stems from the improper handling of the Delay OTP grace flag (`mov_last_verified_dttm`), which is stored in the WordPress `user_meta` table keyed only by user ID. This metadata lacks binding to specific session tokens, IP addresses, or device identifiers. 

When a site is configured with OTP-only login (`wp_login_skip_password=1`) and Delay OTP Verification (`wp_login_delay_otp=1`), an attacker can trigger the `mo_delay_otp_process()` function to short-circuit the standard authentication workflow. By submitting a target username along with the `mo_wp_login_intent=otp` parameter and an arbitrary password, an attacker can inherit an existing user's grace period window, effectively logging in as that user without valid credentials. This impacts any user account, including administrators, provided they fall within the configured delay interval.

## Impact

Successful exploitation allows unauthenticated attackers to achieve full account takeover of any WordPress user on the target site. Given the plugin's potential to affect administrator accounts, this vulnerability can lead to complete site compromise, including the execution of arbitrary code via administrative plugin or theme management, configuration changes, and data exfiltration.

## Recommendation

* Update the miniOrange OTP Login, Verification and SMS Notifications plugin to version 5.5.9 or later immediately to resolve CVE-2026-103895.
* Monitor web server access logs for HTTP POST requests directed at the WordPress login interface containing the parameter `mo_wp_login_intent=otp`.
* Disable `wp_login_skip_password` and `wp_login_delay_otp` settings in the plugin configuration as a temporary mitigation until the software is patched.
