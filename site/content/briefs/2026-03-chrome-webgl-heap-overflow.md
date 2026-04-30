---
title: 'CVE-2026-4675: Google Chrome WebGL Heap Buffer Overflow Vulnerability'
slug: 2026-03-chrome-webgl-heap-overflow
description: A heap buffer overflow vulnerability (CVE-2026-4675) exists in Google Chrome's WebGL implementation prior to version 146.0.7680.165, allowing a remote attacker to perform an out-of-bounds memory read via a specially crafted HTML page, potentially leading to information disclosure or arbitrary code execution.
date: "2026-03-25T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-4675
  - heap-buffer-overflow
  - webgl
  - chrome
  - remote-code-execution
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: 'Command and Scripting Interpreter: PowerShell'
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4675
  - https://chromereleases.googleblog.com/2026/03/stable-channel-update-for-desktop_23.html
  - https://issues.chromium.org/issues/488270257
rules:
  - title: Detect Suspicious WebGL Function Calls in Chrome
    description: Detects potentially malicious HTML pages exploiting WebGL vulnerabilities by monitoring for unusual WebGL function calls within a Chrome process.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - process_creation
      - windows
  - title: Detect Out-of-Bounds Memory Access in Chrome via WebGL
    description: This rule detects potential exploitation of memory corruption vulnerabilities in Chrome's WebGL implementation based on memory access violations.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-4675 describes a heap buffer overflow vulnerability affecting the WebGL component of Google Chrome. Specifically, versions prior to 146.0.7680.165 are susceptible. An attacker can exploit this vulnerability by crafting a malicious HTML page that, when rendered by a vulnerable Chrome browser, triggers an out-of-bounds memory read due to the heap buffer overflow in WebGL. The Chromium security team rated this as a "High" severity issue. Successful exploitation can lead to information…
