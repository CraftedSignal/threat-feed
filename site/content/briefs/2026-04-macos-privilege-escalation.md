---
title: 'CVE-2024-44250: macOS Sequoia Privilege Escalation Vulnerability'
slug: 2026-04-macos-privilege-escalation
description: CVE-2024-44250 is a permission issue in macOS Sequoia 15.1 that allows an application to execute arbitrary code outside of its sandbox or with elevated privileges, potentially leading to full system compromise.
date: "2026-04-02T19:18:28Z"
severities:
  - high
tags:
  - privilege-escalation
  - macos
  - cve-2024-44250
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2024-44250
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2024-44250
  - https://support.apple.com/en-us/121564
rules:
  - title: Detect Suspicious Process Execution from /tmp on macOS
    description: Detects processes executing directly from the /tmp directory, which can be indicative of exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - macos
  - title: Detect application modification of system binaries
    description: Detects applications attempting to modify critical system binaries, which may indicate privilege escalation abuse.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1574.001
    data_sources:
      - file_event
      - macos
rules_count: 2
---

CVE-2024-44250 is a vulnerability affecting macOS Sequoia 15.1. It's a permission issue that allows a malicious application to bypass its designated sandbox and execute arbitrary code with elevated privileges. This means an attacker could potentially gain unauthorized access to sensitive data, modify system settings, or even take complete control of the affected system. The vulnerability was disclosed and patched by Apple in macOS Sequoia 15.1. Successful exploitation could lead to significant…
