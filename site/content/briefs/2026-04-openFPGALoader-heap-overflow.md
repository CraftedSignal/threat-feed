---
title: Heap-Buffer-Overflow Read Vulnerability in openFPGALoader (CVE-2026-35170)
slug: 2026-04-openFPGALoader-heap-overflow
description: A heap-buffer-overflow read vulnerability in openFPGALoader 1.1.1 and earlier allows out-of-bounds heap memory access when parsing a crafted .bit file, potentially leading to denial of service or information disclosure.
date: "2026-04-06T20:16:25Z"
severities:
  - medium
tags:
  - heap-buffer-overflow
  - openFPGALoader
  - denial-of-service
  - information-disclosure
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
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Hardware Additions
cves:
  - id: CVE-2026-35170
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35170
  - https://github.com/trabucayre/openFPGALoader/security/advisories/GHSA-v59x-fvpj-j22x
rules:
  - title: Detect openFPGALoader Processing Malformed Bit Files
    description: Detects potential exploitation attempts of CVE-2026-35170 by monitoring for suspicious command-line arguments used with openFPGALoader.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - process_creation
      - linux
  - title: Detect openFPGALoader Executing from Unusual Location
    description: Detects openFPGALoader executing from a non-standard directory, which could indicate malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A heap-buffer-overflow read vulnerability has been identified in openFPGALoader, a utility designed for programming FPGAs. The vulnerability, assigned CVE-2026-35170, affects version 1.1.1 and earlier. Specifically, the flaw resides within the `BitParser::parseHeader()` function. By crafting a malicious .bit file, an attacker can trigger an out-of-bounds read, leading to potential information disclosure or a denial-of-service condition. It is important to note that exploiting this vulnerability…
