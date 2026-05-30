---
title: 'CVE-2026-7459: Simple History WordPress Plugin Account Takeover Vulnerability'
slug: 2026-05-simple-history-account-takeover
description: CVE-2026-7459 is an authenticated account takeover vulnerability in the Simple History WordPress plugin where a subscriber-level user can read password reset emails and escalate privileges to an administrator account.
date: "2026-05-30T10:16:58Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - account-takeover
  - privilege-escalation
  - cve
vendors:
  - WordPress
products:
  - Simple History – Track, Log, and Audit WordPress Changes plugin
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-7459
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7459
  - CVE-2026-7459
rules:
  - title: Detect Simple History Password Reset Email Access
    description: Detects CVE-2026-7459 exploitation — Access to the password reset email context via Simple History API
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555.004
    data_sources:
      - webserver
  - title: Detect Simple History Event Context Access
    description: Detects unauthorized access to event contexts in Simple History logs.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 2
---

CVE-2026-7459 affects the Simple History – Track, Log, and Audit WordPress Changes plugin for WordPress, versions up to and including 5.26.0. An authenticated subscriber-level user can exploit the vulnerability to read the full context of Simple History events, including password reset emails, via the event reaction endpoints (react_to_event() / unreact_to_event()). The vulnerability stems from insufficient permission checks in the `get_items_permissions_check()` function, which only verifies the user is logged in, failing to enforce logger-specific capability checks. Successful exploitation allows an attacker to extract password reset keys for other users, including administrators, and ultimately take over their accounts. Note that the experimental features option (simple_history_experimental_features_enabled) must be enabled for the vulnerability to be exploitable; this option is not enabled by default.

## Attack Chain

1. The attacker obtains a subscriber-level account on the target WordPress site.
2. The administrator enables the experimental features option within the Simple History plugin.
3. The attacker navigates to the WordPress lost password form and requests a password reset for the administrator account. This triggers a `user_requested_password_reset_link` event in the Simple History log.
4. The attacker sends a POST request to `/wp-json/simple-history/v1/events/<id>/react` with the `_fields=context` parameter, attempting to brute-force the event ID.
5. If the correct event ID for the password reset event is found, the server responds with the full event context, including the password reset email body within the `context.message` field.
6. The attacker extracts the password reset key from the `context.message` field.
7. The attacker uses the extracted reset key to complete the password reset process for the administrator account.
8. The attacker logs in to the WordPress site with the compromised administrator credentials, achieving full account takeover.

## Impact

Successful exploitation of CVE-2026-7459 allows an attacker to gain complete control over a WordPress website by compromising an administrator account. This can lead to defacement of the website, installation of malicious plugins or themes, data theft, and further compromise of the underlying server. Since exploitation requires the experimental features option to be enabled, the number of affected sites might be lower than sites with the plugin installed.

## Recommendation

*   Upgrade to a patched version of the Simple History plugin (later than 5.26.0) to remediate CVE-2026-7459.
*   Disable the experimental features option (simple_history_experimental_features_enabled) in the Simple History plugin settings as a temporary mitigation if upgrading is not immediately possible.
*   Deploy the Sigma rule `Detect Simple History Password Reset Email Access` to your SIEM and tune for your environment to detect potential exploitation attempts.
*   Deploy the Sigma rule `Detect Simple History Event Context Access` to detect unauthorized access to event contexts in Simple History logs.
