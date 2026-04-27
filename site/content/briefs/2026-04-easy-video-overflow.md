---
title: Easy Video to iPod Converter 1.6.20 Local Buffer Overflow Vulnerability
slug: 2026-04-easy-video-overflow
description: Easy Video to iPod Converter 1.6.20 is vulnerable to a local buffer overflow in the user registration field, allowing a local attacker to overwrite the structured exception handler (SEH) by providing a crafted payload exceeding 996 bytes in the username field, potentially leading to arbitrary code execution with user privileges.
date: "2026-04-12T13:16:32Z"
severities:
  - high
tags:
  - cve-2019-25701
  - buffer-overflow
  - local-privilege-escalation
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
cves:
  - id: CVE-2019-25701
    cvss: 8.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25701
  - https://www.exploit-db.com/exploits/46255
  - https://www.vulncheck.com/advisories/easy-video-to-ipod-converter-local-buffer-overflow-seh
rules:
  - title: Suspicious Process Creation from Easy Video to iPod Converter
    description: Detects suspicious process creations spawned by the Easy Video to iPod Converter executable, which may indicate exploitation of CVE-2019-25701.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.001
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Registry Modification by Easy Video to iPod Converter
    description: Detects registry modifications performed by the Easy Video to iPod Converter process. This may indicate persistence or other malicious activity related to the exploitation of CVE-2019-25701.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

Easy Video to iPod Converter version 1.6.20 is susceptible to a local buffer overflow vulnerability (CVE-2019-25701) within the user registration functionality. This vulnerability allows an attacker with local access to the system to potentially overwrite the Structured Exception Handler (SEH) by providing a crafted payload larger than 996 bytes in the username field during registration. This could lead to arbitrary code execution within the context of the user running the vulnerable…
