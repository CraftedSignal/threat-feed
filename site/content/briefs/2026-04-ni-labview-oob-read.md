---
title: NI LabVIEW Out-of-Bounds Read Vulnerability (CVE-2026-32863)
slug: 2026-04-ni-labview-oob-read
description: A memory corruption vulnerability due to an out-of-bounds read in NI LabVIEW's `sentry_transaction_context_set_operation()` function could lead to information disclosure or arbitrary code execution by opening a specially crafted VI file.
date: "2026-04-07T20:16:26Z"
severities:
  - high
tags:
  - cve-2026-32863
  - labview
  - out-of-bounds read
  - memory corruption
  - arbitrary code execution
  - information disclosure
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
cves:
  - id: CVE-2026-32863
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32863
  - https://www.ni.com/en/support/security/available-critical-and-security-updates-for-ni-software/2026/memory-corruption-vulnerabilities-in-ni-labview.html
rules:
  - title: LabVIEW Suspicious Child Process
    description: Detects LabVIEW spawning a suspicious child process, potentially indicating code execution after successful exploitation of CVE-2026-32863.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: LabVIEW Network Connection by Uncommon Process
    description: Detects network connections initiated by LabVIEW child processes outside the standard installation directory, which may indicate post-exploitation activity.
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

A critical memory corruption vulnerability (CVE-2026-32863) exists in National Instruments (NI) LabVIEW, specifically within the `sentry_transaction_context_set_operation()` function. This out-of-bounds read vulnerability can be exploited by an attacker who successfully convinces a LabVIEW user to open a malicious, specially crafted VI file. Successful exploitation could lead to information disclosure, potentially exposing sensitive data handled by LabVIEW, or even allow for arbitrary code…
