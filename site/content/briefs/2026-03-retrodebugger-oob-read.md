---
title: RetroDebugger Out-of-Bounds Read Vulnerability (CVE-2026-4753)
slug: 2026-03-retrodebugger-oob-read
description: RetroDebugger before v0.64.72 is vulnerable to an out-of-bounds read (CVE-2026-4753), potentially leading to information disclosure or denial of service.
date: "2026-03-24T06:16:23Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve-2026-4753
  - out-of-bounds read
  - retrodebugger
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Standard System Discovery
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4753
  - https://github.com/slajerek/RetroDebugger/pull/97
ioc_counts:
  email: 1
rules:
  - title: Detect RetroDebugger Out-of-Bounds Read Attempt
    description: Detects potential exploitation of CVE-2026-4753 based on RetroDebugger process crashes.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
  - title: Detect RetroDebugger Process Start
    description: Detects the start of the RetroDebugger process. This can be useful for baselining and investigating unusual activity.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

RetroDebugger before version v0.64.72 contains an out-of-bounds read vulnerability, identified as CVE-2026-4753. This flaw could allow an attacker to read sensitive information from memory locations outside of the intended buffer, potentially leading to information disclosure or causing the application to crash, resulting in a denial of service. The vulnerability was reported by the Government Technology Agency of Singapore Cyber Security Group (GovTech CSG). Given the critical CVSS score of…
