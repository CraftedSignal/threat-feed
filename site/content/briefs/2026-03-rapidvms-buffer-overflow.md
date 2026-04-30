---
title: linkingvision rapidvms Improper Memory Buffer Restriction Vulnerability (CVE-2026-33847)
slug: 2026-03-rapidvms-buffer-overflow
description: An Improper Restriction of Operations within the Bounds of a Memory Buffer vulnerability in linkingvision rapidvms before PR#96 could lead to arbitrary code execution.
date: "2026-03-24T06:16:21Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve
  - buffer-overflow
  - rapidvms
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33847
  - https://github.com/linkingvision/rapidvms/pull/98
ioc_counts:
  email: 1
rules:
  - title: Detect rapidvms Suspicious Child Process
    description: Detects rapidvms spawning a shell, indicating potential exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect rapidvms buffer overflow attempt via command line
    description: Detects possible buffer overflow attempt by monitoring command line of rapidvms for suspicious arguments.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

An Improper Restriction of Operations within the Bounds of a Memory Buffer vulnerability, identified as CVE-2026-33847, exists in linkingvision rapidvms. The vulnerability affects versions prior to pull request #96. This flaw could allow an attacker to potentially execute arbitrary code or cause a denial-of-service condition by writing past allocated buffer limits. The vulnerability was reported by the Government Technology Agency of Singapore Cyber Security Group (GovTech CSG). Successful…
