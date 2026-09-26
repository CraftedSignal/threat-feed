---
title: Authentication Bypass in miniOrange OTP Login Plugin
slug: 2026-09-miniorange-bypass
description: An authentication bypass vulnerability in the miniOrange OTP Login, Verification and SMS Notifications plugin allows unauthenticated attackers to log in as administrators by abusing a flawed login intent parameter.
date: "2026-09-26T19:00:02Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:miniorange:otp_login_verification_and_sms_notifications:*:*:*:*:*:*:*:*
tags:
  - wordpress
  - authentication-bypass
  - cve-2026-85984
vendors:
  - miniOrange
products:
  - OTP Login, Verification and SMS Notifications (<= 5.5.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550.001
    technique_name: Use Alternate Authentication Material
    evidence: This makes it possible for unauthenticated attackers to log in as any existing administrator account by supplying only a known username and an empty password alongside mo_wp_login_intent=otp, with no password or OTP verification required.
    confidence_band: high
cves:
  - id: CVE-2026-85984
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85984
rules:
  - title: Detects CVE-2026-85984 Exploitation - Authentication Bypass Attempt
    description: Detects exploitation attempts by identifying HTTP POST requests containing the malicious mo_wp_login_intent parameter directed at the WordPress login endpoint.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1550.001
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch miniOrange OTP plugin to version 5.5.6 or later
      owner: IT Operations
      due: 24h
      evidence: Plugin vulnerable in versions <= 5.5.5
    - action: Monitor web logs for 'mo_wp_login_intent=otp' strings
      owner: SOC
      due: immediate
      evidence: Exploit requires submitting this specific parameter
  mitigation_plan:
    - priority: immediate
      action: Disable 'Admin OTP Bypass' setting in plugin configuration
      owner: IT Operations
      addresses: CVE-2026-85984
      evidence: Exploitation is conditional on a site administrator having enabled Admin OTP Bypass
---

The miniOrange OTP Login, Verification and SMS Notifications plugin for WordPress (all versions up to and including 5.5.5) contains a critical authentication bypass vulnerability identified as CVE-2026-85984. The flaw resides within the mo_by_pass_login() function, where improper handling of the mo_wp_login_intent POST parameter allows an authentication bypass when specific administrative configurations are active. If a site administrator has enabled 'WP Login OTP', 'Login with Only OTP', 'Allow Users to Login with Username and Password', and 'Admin OTP Bypass', the system fails to validate credentials. An attacker simply provides a valid administrative username and the parameter mo_wp_login_intent=otp. The plugin erroneously skips the standard wp_authenticate_username_password() check and resolves the WP_User account solely based on the username, granting full access without a password or OTP verification. This vulnerability poses a severe risk to WordPress instances configured with these specific security settings.

## Impact

Successful exploitation allows an unauthenticated attacker to gain full administrative access to the affected WordPress site. This provides the attacker with complete control over the site content, user management, and plugin configuration, which could lead to further compromise through malicious plugin uploads, data exfiltration, or complete site takeover.

## Recommendation

Prioritize the immediate update of the miniOrange OTP Login, Verification and SMS Notifications plugin to a version beyond 5.5.5. If patching is not immediately feasible, disable the 'Admin OTP Bypass' option within the plugin settings to mitigate the primary vector for this bypass. Review administrative account login logs for suspicious activity occurring without standard password-based authentication steps.
