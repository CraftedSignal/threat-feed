---
title: V-SFT v6.2.10.0 Stack-Based Buffer Overflow (CVE-2026-32925)
slug: 2026-04-v-sft-buffer-overflow
description: V-SFT versions 6.2.10.0 and prior are vulnerable to a stack-based buffer overflow (CVE-2026-32925) in the VS6ComFile!CV7BaseMap::WriteV7DataToRom function, potentially leading to arbitrary code execution when processing a crafted V7 file.
date: "2026-04-01T23:17:02Z"
severities:
  - critical
tags:
  - cve-2026-32925
  - stack-based-buffer-overflow
  - v-sft
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
cves:
  - id: CVE-2026-32925
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32925
  - https://felib.fujielectric.co.jp/en/M10010/M20060/document_detail/5d9dd71d-9494-41a4-aa5c-8e6b8b21066b?region=en-glb
  - https://jvn.jp/en/vu/JVNVU90448293/
rules:
  - title: Detect Suspicious V-SFT Child Processes
    description: Detects suspicious child processes spawned by V-SFT, potentially indicating code execution after exploiting CVE-2026-32925.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect V-SFT Writing V7 File
    description: Detects V-SFT writing V7 file, which could be abused by attacker by overwriting a legitimate V7 file.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

V-SFT versions 6.2.10.0 and earlier are susceptible to a critical stack-based buffer overflow vulnerability identified as CVE-2026-32925. This flaw resides within the `VS6ComFile!CV7BaseMap::WriteV7DataToRom` function. The vulnerability is triggered when the software processes a specially crafted V7 file. A successful exploit could allow an attacker to execute arbitrary code within the context of the application. This poses a significant risk to systems utilizing affected versions of V-SFT, as…
