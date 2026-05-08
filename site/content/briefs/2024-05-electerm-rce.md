---
title: Electerm Path Traversal Vulnerability Leads to Arbitrary Code Execution
slug: 2024-05-electerm-rce
description: Electerm versions prior to 3.7.16 are vulnerable to path traversal, leading to arbitrary code execution through unsanitized widget identifiers.
date: "2024-05-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - path-traversal
  - code-execution
  - electerm
vendors:
  - electerm
products:
  - electerm (< 3.7.16)
affected_os:
  - Windows 10
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1202
    technique_name: Indirect Command Execution
cves:
  - id: CVE-2026-43940
    cvss: 8.4
references:
  - https://github.com/advisories/GHSA-f77v-9vpc-6pjm
  - https://github.com/electerm/electerm
  - https://github.com/electerm/electerm/security
rules:
  - title: Detect Suspicious Electerm Widget Loading
    description: Detects CVE-2026-43940 exploitation — loading of Electerm widgets with path traversal sequences in the filename.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1202
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Electerm Widget Loading (Linux)
    description: Detects CVE-2026-43940 exploitation — loading of Electerm widgets with path traversal sequences in the filename on Linux.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1202
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Electerm versions before 3.7.16 are susceptible to a critical path traversal vulnerability within the `runWidget` function located in `src/app/widgets/load-widget.js`. This function insecurely constructs file paths by concatenating user-supplied widget identifiers without proper sanitization. Successful exploitation of CVE-2026-43940 allows an attacker with JavaScript execution within the renderer process to load and execute arbitrary JavaScript files anywhere on the victim’s filesystem. This results in local code execution with the full privileges of the Electerm process, potentially leading to complete system compromise on Windows 10 and Linux systems. The vulnerability was confirmed on v3.7.9, Win10.

## Attack Chain

1. Attacker gains initial JavaScript execution within Electerm's renderer process, possibly via a malicious plugin or XSS.
2. The attacker crafts a malicious widget identifier containing path traversal sequences (e.g., `../`).
3. The malicious widget identifier is passed to the `runWidget` function via an asynchronous IPC handler.
4. The `runWidget` function concatenates the unsanitized widget identifier into a file path: `widget-${widgetId}.js`.
5. The resulting file path includes the path traversal sequences, allowing access to arbitrary files.
6. The `require()` function attempts to load and execute the JavaScript file at the attacker-controlled path.
7. If the path traversal is successful, an arbitrary JavaScript file is executed with Electerm process privileges.
8. The attacker achieves arbitrary code execution, leading to complete system compromise.

## Impact

Successful exploitation of this vulnerability grants an attacker local code execution with the privileges of the Electerm process. This enables them to perform actions such as installing malware, stealing sensitive data, or compromising the entire system. The vulnerability affects Electerm users on Windows 10 and Linux systems who are running versions prior to 3.7.16. A successful attack could lead to complete system compromise.

## Recommendation

*   Upgrade Electerm to version 3.7.16 or later to patch CVE-2026-43940.
*   Deploy the Sigma rule `Detect Suspicious Electerm Widget Loading` to your SIEM and tune for your environment to detect path traversal attempts.
*   Enable process creation logging on Windows and Linux systems to enhance visibility and enable the `Detect Suspicious Electerm Widget Loading` rule.
