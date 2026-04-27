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

The Users manager – PN plugin, versions up to and including 1.1.15, contains a critical privilege escalation vulnerability (CVE-2026-4003). The vulnerability resides in the `userspn_ajax_nopriv_server()` function, specifically within the `userspn_form_save` case. A flawed authorization check enables unauthenticated users to bypass security controls when a non-empty `user_id` is provided. This allows them to update arbitrary user meta using the `update_user_meta()` function without proper…
