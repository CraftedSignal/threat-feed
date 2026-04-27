---
title: node-tesseract-ocr OS Command Injection Vulnerability
slug: 2026-03-node-tesseract-ocr-command-injection
description: The node-tesseract-ocr npm package through version 2.2.1 is vulnerable to OS command injection due to improper sanitization of the file path parameter in the recognize() function, potentially allowing for arbitrary command execution.
date: "2026-03-26T12:00:00Z"
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

The node-tesseract-ocr npm package, a Node.js wrapper for Tesseract OCR, is vulnerable to OS command injection (CVE-2026-26832) in versions 2.2.1 and earlier. The vulnerability exists within the `recognize()` function located in `src/index.js`. The `file path` parameter, used to specify the image for OCR processing, is directly concatenated into a shell command string without proper sanitization. This unsanitized string is then passed to `child_process.exec()`, enabling attackers to inject…
