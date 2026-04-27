---
title: NI LabVIEW Memory Corruption Vulnerability (CVE-2026-32862)
slug: 2026-04-ni-labview-rce
description: A memory corruption vulnerability (CVE-2026-32862) in NI LabVIEW versions 2026 Q1 (26.1.0) and prior, stemming from an out-of-bounds write in ResFileFactory::InitResourceMgr(), can lead to information disclosure or arbitrary code execution if a user opens a malicious VI file.
date: "2026-04-07T20:16:24Z"
severities:
  - high
tags:
  - cve-2026-32862
  - ni-labview
  - memory-corruption
  - rce
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
cves:
  - id: CVE-2026-32862
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32862
  - https://www.ni.com/en/support/security/available-critical-and-security-updates-for-ni-software/2026/memory-corruption-vulnerabilities-in-ni-labview.html
rules:
  - title: Detect Suspicious LabVIEW File Opening
    description: Detects LabVIEW opening a .VI file, which may indicate exploitation of CVE-2026-32862.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - process_creation
      - windows
  - title: Detect LabVIEW process attempting network connection
    description: Detects LabVIEW initiating network connections which may be unusual, possibly indicating code execution after CVE-2026-32862 exploitation.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

A critical memory corruption vulnerability, identified as CVE-2026-32862, exists within NI LabVIEW's ResFileFactory::InitResourceMgr() function. This out-of-bounds write vulnerability can be exploited to achieve both information disclosure and arbitrary code execution on affected systems. The attack vector involves enticing a user to open a specially crafted VI (Virtual Instrument) file within LabVIEW. Successful exploitation of this vulnerability could allow an attacker to compromise the…
