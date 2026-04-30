---
title: node-tesseract-ocr OS Command Injection Vulnerability
slug: 2026-03-node-tesseract-ocr-command-injection
description: The node-tesseract-ocr npm package through version 2.2.1 is vulnerable to OS command injection due to improper sanitization of the file path parameter in the recognize() function, potentially allowing for arbitrary command execution.
date: "2026-03-26T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - command-injection
  - nodejs
  - tesseract-ocr
  - cve-2026-26832
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-26832
  - https://github.com/zapolnoch/node-tesseract-ocr
  - https://github.com/zapolnoch/node-tesseract-ocr/blob/master/src/index.js
  - https://github.com/zebbernCVE/CVE-2026-26832
  - https://www.npmjs.com/package/node-tesseract-ocr
iocs:
  - type: url
    value: https://github.com/zapolnoch/node-tesseract-ocr
  - type: url
    value: https://github.com/zapolnoch/node-tesseract-ocr/blob/master/src/index.js
  - type: url
    value: https://github.zebbernCVE/CVE-2026-26832
  - type: url
    value: https://www.npmjs.com/package/node-tesseract-ocr
  - type: email
    value: '[email protected]'
ioc_counts:
  email: 1
  url: 4
rules:
  - title: Suspicious Process Execution from Node.js
    description: Detects suspicious processes spawned by Node.js which could indicate command injection.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1212
    data_sources:
      - process_creation
      - windows
  - title: Linux suspicious Process Execution from Node.js
    description: Detects suspicious processes spawned by Node.js which could indicate command injection on Linux.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1212
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The node-tesseract-ocr npm package, a Node.js wrapper for Tesseract OCR, is vulnerable to OS command injection (CVE-2026-26832) in versions 2.2.1 and earlier. The vulnerability exists within the `recognize()` function located in `src/index.js`. The `file path` parameter, used to specify the image for OCR processing, is directly concatenated into a shell command string without proper sanitization. This unsanitized string is then passed to `child_process.exec()`, enabling attackers to inject arbitrary commands that are executed by the system. Exploitation can lead to complete system compromise, data exfiltration, or denial of service.

## Attack Chain

1.  An attacker crafts a malicious file path containing OS commands.
2.  The attacker passes the malicious file path to the `recognize()` function within the `node-tesseract-ocr` package.
3.  The `recognize()` function concatenates the attacker-controlled file path into a command string.
4.  The command string, now containing injected OS commands, is passed to `child_process.exec()`.
5.  `child_process.exec()` executes the command string.
6.  The injected OS commands are executed by the system with the privileges of the Node.js process.
7.  The attacker gains arbitrary code execution on the target system.
8.  The attacker can then perform actions such as installing malware, creating new user accounts, or exfiltrating sensitive data.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary commands on the server hosting the Node.js application. This can lead to complete system compromise, potentially impacting all data and services hosted on the compromised server. The severity is heightened because the vulnerability is remotely exploitable and requires no user interaction. Systems using affected versions of `node-tesseract-ocr` are at high risk.

## Recommendation

*   Upgrade the `node-tesseract-ocr` package to a patched version that addresses CVE-2026-26832 if available.
*   Implement strict input validation and sanitization for the file path parameter passed to the `recognize()` function, mitigating command injection attempts.
*   Monitor process creation events for unusual processes spawned by Node.js (`node.exe` or `node`) to detect potential exploitation using the provided Sigma rule.
*   Review and audit all uses of `child_process.exec()` within Node.js applications to identify and remediate other potential command injection vulnerabilities.
