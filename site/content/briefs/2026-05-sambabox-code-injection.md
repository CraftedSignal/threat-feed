---
title: SambaBox OS Command Injection Vulnerability (CVE-2026-3120)
slug: 2026-05-sambabox-code-injection
description: SambaBox versions 5.1 to before 5.3 are vulnerable to OS command injection via improper control of code generation (CVE-2026-3120), potentially allowing attackers with high privileges to execute arbitrary commands on the underlying system.
date: "2026-05-04T12:16:29Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - code-injection
  - os-command-injection
  - cve-2026-3120
vendors:
  - Profelis Information and Consulting Trade and Industry Limited Company
products:
  - SambaBox (>= 5.1, < 5.3)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-3120
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3120
  - https://www.usom.gov.tr/bildirim/tr-26-0155
rules:
  - title: Detect SambaBox Command Injection
    description: Detects potential command injection attempts in SambaBox by monitoring for suspicious process execution originating from the SambaBox application.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - process_creation
      - linux
  - title: Detect Web Requests with Suspicious OS Commands
    description: Detects web requests containing suspicious OS commands.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-3120 is a critical vulnerability affecting SambaBox, a product by Profelis Information and Consulting Trade and Industry Limited Company. This vulnerability, categorized as an Improper Control of Generation of Code ('Code Injection'), allows for OS Command Injection. Specifically, SambaBox versions 5.1 up to (but not including) version 5.3 are affected. An attacker with high privileges can exploit this vulnerability to execute arbitrary commands on the underlying operating system, potentially leading to full system compromise. This vulnerability was reported by the Computer Emergency Response Team of the Republic of Turkey (USOM). Defenders should patch affected systems immediately or apply mitigations to prevent exploitation.

## Attack Chain

1. An attacker with high privileges gains access to the SambaBox management interface.
2. The attacker crafts a malicious request containing an OS command within a vulnerable input field.
3. The SambaBox application fails to properly sanitize or validate the input.
4. The application generates code incorporating the unsanitized input.
5. The generated code is executed by the underlying operating system.
6. The injected OS command is executed with the privileges of the SambaBox application.
7. The attacker gains the ability to execute arbitrary commands on the server.
8. The attacker leverages the command execution to achieve persistence, escalate privileges further, or exfiltrate sensitive data.

## Impact

Successful exploitation of CVE-2026-3120 allows an attacker to execute arbitrary commands on the SambaBox server. This could lead to complete system compromise, including data theft, modification, or destruction. The vulnerability affects SambaBox installations from version 5.1 before 5.3, potentially impacting all organizations using these versions. Given the high CVSS score of 7.2, this vulnerability poses a significant risk.

## Recommendation

*   Upgrade SambaBox to version 5.3 or later to patch CVE-2026-3120.
*   Apply the following Sigma rule to detect potential exploitation attempts by monitoring for suspicious process execution: "Detect SambaBox Command Injection".
*   Monitor web server logs for unusual requests targeting SambaBox applications, specifically looking for attempts to inject OS commands.
