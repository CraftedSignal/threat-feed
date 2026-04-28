---
title: WordPress Users Manager Plugin Privilege Escalation Vulnerability (CVE-2026-4003)
slug: 2026-04-wordpress-privesc
description: The Users manager – PN plugin for WordPress is vulnerable to privilege escalation, allowing unauthenticated attackers to modify arbitrary user metadata by exploiting a flawed authorization check in the userspn_ajax_nopriv_server() function (CVE-2026-4003).
date: "2026-04-08T05:16:06Z"
severities:
  - critical
tags:
  - wordpress
  - privilege-escalation
  - cve-2026-4003
  - plugin
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-4003
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4003
rules:
  - title: Detect WordPress Users Manager Plugin Privilege Escalation Attempt
    description: Detects potential exploitation attempts of CVE-2026-4003 by monitoring for POST requests to wp-admin/admin-ajax.php with the userspn_form_save action and a non-empty user_id.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect WordPress userspn_secret_token User Meta Modification
    description: Detects attempts to modify the `userspn_secret_token` user meta value via the vulnerable AJAX endpoint.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Users manager – PN plugin, versions up to and including 1.1.15, contains a critical privilege escalation vulnerability (CVE-2026-4003). The vulnerability resides in the `userspn_ajax_nopriv_server()` function, specifically within the `userspn_form_save` case. A flawed authorization check enables unauthenticated users to bypass security controls when a non-empty `user_id` is provided. This allows them to update arbitrary user meta using the `update_user_meta()` function without proper authorization. The nonce, 'userspn-nonce', is exposed to all visitors via `wp_localize_script` on the public `wp_enqueue_scripts` hook, making the nonce check ineffective. Successful exploitation allows unauthenticated attackers to modify user metadata, including the `userspn_secret_token` field, leading to potential account takeover and administrative control of the WordPress site. This vulnerability poses a significant risk to any WordPress site using the affected plugin.

## Attack Chain

1.  The attacker identifies a WordPress site using the vulnerable "Users manager – PN" plugin (<= 1.1.15).
2.  The attacker accesses the publicly exposed 'userspn-nonce' value via the `wp_enqueue_scripts` hook.
3.  The attacker crafts a malicious AJAX request to the `userspn_ajax_nopriv_server()` endpoint with the `userspn_form_save` action and a non-empty `user_id` parameter.
4.  The flawed authorization check in `userspn_ajax_nopriv_server()` bypasses authentication due to the supplied `user_id` not being empty.
5.  The attacker injects arbitrary user meta values, including the `userspn_secret_token` or other sensitive fields.
6.  The `update_user_meta()` function is called, updating the targeted user's metadata with the attacker-supplied values.
7.  The attacker exploits the modified `userspn_secret_token` or other injected admin-level capabilities to escalate privileges.
8.  The attacker gains administrative access to the WordPress site and performs malicious actions such as installing backdoors, modifying content, or exfiltrating data.

## Impact

Successful exploitation of CVE-2026-4003 allows unauthenticated attackers to escalate privileges to administrator level on affected WordPress sites. This could lead to complete compromise of the website, including data theft, defacement, or use of the server for malicious purposes. The severity is heightened by the ease of exploitation. Because no IOCs are present in the source, it is impossible to determine the scope of exploitation.

## Recommendation

*   Apply the vendor-supplied patch or upgrade the "Users manager – PN" plugin to a version greater than 1.1.15 to remediate CVE-2026-4003.
*   Monitor web server logs for POST requests to `/wp-admin/admin-ajax.php` with the action `userspn_form_save` and a non-empty `user_id` parameter to detect potential exploitation attempts using the provided Sigma rule.
*   Implement rate limiting on AJAX endpoints to mitigate potential brute-force attacks targeting the vulnerability.
