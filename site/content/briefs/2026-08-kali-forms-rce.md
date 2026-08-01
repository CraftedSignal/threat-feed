---
title: Remote Code Execution in Kali Forms WordPress Plugin
slug: 2026-08-kali-forms-rce
description: Unauthenticated attackers can achieve remote code execution in Kali Forms versions up to 2.4.20 by exploiting insufficient validation of the thisPermalink field within the _save_data function.
date: "2026-08-01T09:50:14Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - wordpress
  - rce
products:
  - Kali Forms — Contact Form & Drag-and-Drop Builder (<= 2.4.20)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to execute code on the server.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: This allows an unauthenticated user to trigger arbitrary code execution on the server.
    confidence_band: high
cves:
  - id: CVE-2026-16144
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16144
rules:
  - title: Detects CVE-2026-16144 Exploitation - Potential RCE in Kali Forms
    description: Detects exploitation attempts against CVE-2026-16144 where a POST request targets the Kali Forms plugin with malicious input in the thisPermalink parameter.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

The Kali Forms - Contact Form & Drag-and-Drop Builder plugin for WordPress is vulnerable to Remote Code Execution (RCE) in all versions up to and including 2.4.20. The vulnerability resides in the _save_data function, where improper input validation occurs on the 'thisPermalink' field. Specifically, the application fails to validate the value before it overwrites a trusted callable placeholder. An attacker can supply a crafted string that reaches the call_user_func() function within _save_data(). This allows an unauthenticated user to trigger arbitrary code execution on the server. Exploitation requires that a target form defines a field name matching one of the reserved placeholder keys: 'thisPermalink', 'entryCounter', or 'submission_link', as the check_if_placeholders_changed() function only processes POST keys present in the form's field_type_map. Organizations using this plugin should update to a patched version immediately.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to execute arbitrary code on the underlying web server hosting the WordPress site. This can lead to full site compromise, data exfiltration, installation of web shells, and potential lateral movement into the hosting environment.

## Recommendation

1. Patch the Kali Forms WordPress plugin to the latest available version that resolves CVE-2026-16144.
2. Implement a Web Application Firewall (WAF) rule to inspect POST requests directed at WordPress plugins, specifically flagging requests containing unexpected PHP function names or serialized objects in fields mapped to placeholder keys like 'thisPermalink'.
3. Audit the configuration of all active forms to ensure no fields are using reserved names that match the affected placeholder keys.
4. Enable server-side logging for web requests and monitor for anomalous execution patterns originating from WordPress plugin directories.
