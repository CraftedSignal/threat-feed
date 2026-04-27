---
title: SiYuan Knowledge Management System Stored XSS Leads to RCE (CVE-2026-39846)
slug: 2026-04-siyuan-rce
description: A stored XSS vulnerability in SiYuan versions prior to 3.6.4 (CVE-2026-39846) allows remote code execution by syncing a malicious note containing a crafted table caption to another user, leading to arbitrary code execution on the victim's machine.
date: "2026-04-07T22:16:23Z"
severities:
  - critical
tags:
  - cve-2026-39846
  - rce
  - xss
  - siyuan
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-39846
    cvss: 9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39846
rules:
  - title: Detect Suspicious SiYuan Table Caption
    description: Detects potential exploitation of the SiYuan RCE vulnerability (CVE-2026-39846) by monitoring for process creations originating from the SiYuan application with suspicious command-line arguments.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.007
    data_sources:
      - process_creation
      - windows
  - title: SiYuan Network Activity
    description: Detects network connections initiated by SiYuan process that may indicate command and control activity after exploitation.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

SiYuan, a personal knowledge management system, is vulnerable to remote code execution (RCE) due to a stored Cross-Site Scripting (XSS) vulnerability. This flaw, identified as CVE-2026-39846, affects versions prior to 3.6.4. The vulnerability stems from unsanitized table caption content within notes. An attacker can craft a malicious note containing a specifically crafted table caption with JavaScript, import this note into a shared workspace, and then wait for another user (the victim) to…
