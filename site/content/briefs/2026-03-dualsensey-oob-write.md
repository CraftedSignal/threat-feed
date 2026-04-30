---
title: Out-of-bounds Write Vulnerability in DualSenseY-v2
slug: 2026-03-dualsensey-oob-write
description: CVE-2026-33850 is an out-of-bounds write vulnerability in WujekFoliarz DualSenseY-v2 before version 54, potentially allowing an attacker to execute arbitrary code or cause a denial-of-service by writing data outside the allocated buffer.
date: "2026-03-24T06:16:22Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve
  - vulnerability
  - oob-write
  - dualsensey-v2
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Software Discovery
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204.002
    technique_name: 'User Execution: Malicious File'
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33850
  - https://github.com/WujekFoliarz/DualSenseY-v2/pull/66
rules:
  - title: Detect DualSenseY-v2 Crash
    description: Detects potential exploitation attempts against DualSenseY-v2 based on application crash events.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - application
      - windows
  - title: Detect DualSenseY-v2 Suspicious Process Creation
    description: Detects potential exploitation attempts of DualSenseY-v2 leading to suspicious process creation.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

An out-of-bounds write vulnerability, identified as CVE-2026-33850, exists in WujekFoliarz DualSenseY-v2 before version 54. This flaw allows an attacker to write data beyond the boundaries of an allocated buffer, potentially leading to arbitrary code execution or a denial-of-service condition. The vulnerability was reported by the Government Technology Agency of Singapore Cyber Security Group (GovTech CSG). Successful exploitation of this vulnerability requires user interaction, as indicated by…
