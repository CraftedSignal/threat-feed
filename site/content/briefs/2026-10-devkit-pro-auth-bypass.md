---
title: Authentication Bypass in DevKit Pro Plugin for WordPress
slug: 2026-10-devkit-pro-auth-bypass
description: An authentication bypass vulnerability in the DevKit Pro WordPress plugin allows unauthenticated attackers to hijack administrator sessions via cookie manipulation and nonce collection.
date: "2026-10-02T04:22:10Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:devkit:devkit_pro:*:*:*:*:*:wordpress:*:*
vendors:
  - WordPress
products:
  - DevKit Pro (<= 2.3.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1187
    technique_name: Forced Authentication
    evidence: The DevKit Pro plugin for WordPress is vulnerable to Authentication Bypass Leading to Administrator Account Takeover
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: This makes it possible for unauthenticated attackers to set the original_user_id cookie ... granting the attacker a full administrator-level authenticated session
    confidence_band: high
cves:
  - id: CVE-2026-14378
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14378
rules:
  - title: Detect CVE-2026-14378 Exploitation - Unauthorized Access to revert_switch
    description: Detects unauthorized POST requests to the revert_switch handler by unauthenticated users.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1187
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Update DevKit Pro plugin to version > 2.3.0
      owner: IT Operations
      due: 24h
      evidence: Plugin vulnerable up to 2.3.0
  mitigation_plan:
    - priority: immediate
      action: Upgrade DevKit Pro to version > 2.3.0
      owner: IT Operations
      addresses: CVE-2026-14378
      evidence: Source states versions up to 2.3.0 are vulnerable
---

The DevKit Pro plugin for WordPress (versions 2.3.0 and earlier) contains a critical authentication bypass vulnerability that facilitates full administrator account takeover. The flaw resides in the `revert_switch` handler, which incorrectly trusts an attacker-provided `original_user_id` cookie to define the target identity for session switching. 

The plugin's logic fails to validate the requester's identity using `current_user_can()`, opting instead to check for the `manage_options` capability on the user ID specified in the cookie. Because the switch-back form and a valid, session-bound nonce are rendered in the `wp_footer` HTML for any visitor, an unauthenticated user can trigger the vulnerability by setting the `original_user_id` cookie to an administrator's ID and submitting a request with the collected nonce. Successful exploitation results in the attacker receiving an authenticated session as the targeted administrator, granting full control over the WordPress site.

## Attack Chain

1. Attacker visits a public-facing page of the WordPress site to trigger the rendering of the `wp_footer`.
2. Attacker inspects the HTML source code of the `wp_footer` to capture a valid, session-bound nonce.
3. Attacker identifies the target administrator's user ID (typically 1).
4. Attacker sets the `original_user_id` cookie in their browser to the captured administrator ID.
5. Attacker sends a POST request to the `revert_switch` handler endpoint with the valid, intercepted nonce.
6. The `revert_switch` handler processes the request, incorrectly trusting the `original_user_id` cookie and verifying the capability against the administrator's account rather than the requestor's.
7. The system calls `wp_set_auth_cookie()` using the administrator's ID, successfully authenticating the attacker as the administrator.

## Impact

Successful exploitation of this vulnerability leads to complete site takeover, as the attacker gains full administrator privileges. This allows for arbitrary code execution, installation of malicious plugins, exfiltration of sensitive database content, and potential distribution of further malware to site visitors. All WordPress installations running DevKit Pro version 2.3.0 or earlier are at risk.

## Recommendation

* Immediately update the DevKit Pro plugin to the latest version (post-2.3.0) to patch the `revert_switch` logic.
* Audit WordPress access logs for anomalous POST requests to the `revert_switch` endpoint originating from unauthenticated sessions.
* Review administrative user accounts for suspicious activities or unexpected additions of new administrator accounts.
* Implement strict access controls for administrative endpoints and consider restricting access to the WordPress dashboard by IP address.
