---
title: pdf-image npm Package Command Injection Vulnerability (CVE-2026-26830)
slug: 2026-03-pdf-image-command-injection
description: The pdf-image npm package through version 2.0.0 is vulnerable to OS command injection via the pdfFilePath parameter due to improper sanitization, potentially leading to arbitrary code execution.
date: "2026-03-25T15:16:38Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - command-injection
  - npm
  - CVE-2026-26830
  - pdf
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-26830
  - https://github.com/mooz/node-pdf-image
  - https://github.com/zebbernCVE/CVE-2026-26830
  - https://www.npmjs.com/package/pdf-image
rules:
  - title: Detect Suspicious PDF Image Command Execution
    description: Detects potential command injection attempts in pdf-image library by monitoring for suspicious child processes spawned by node processes.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious PDF Image Network Connection
    description: Detects potential command injection attempts in pdf-image library by monitoring for suspicious outbound network connections from node processes after pdf processing.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

The pdf-image npm package, up to version 2.0.0, contains a critical vulnerability (CVE-2026-26830) that allows for OS command injection. This vulnerability stems from the way the package handles user-provided file paths when processing PDF files. Specifically, the `constructGetInfoCommand` and `constructConvertCommandForPage` functions utilize `util.format()` to incorporate the `pdfFilePath` parameter directly into shell command strings. These commands are then executed using…
