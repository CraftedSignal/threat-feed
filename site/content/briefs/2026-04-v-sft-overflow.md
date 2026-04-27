---
title: V-SFT Stack-Based Buffer Overflow Vulnerability (CVE-2026-32928)
slug: 2026-04-v-sft-overflow
description: V-SFT versions 6.2.10.0 and prior are susceptible to a stack-based buffer overflow vulnerability that could allow arbitrary code execution when a malicious V7 file is opened.
date: "2026-04-01T23:17:03Z"
severities:
  - high
tags:
  - cve-2026-32928
  - buffer-overflow
  - code-execution
  - v-sft
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2026-32928
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32928
  - https://felib.fujielectric.co.jp/en/M10010/M20060/document_detail/5d9dd71d-9494-41a4-aa5c-8e6b8b21066b?region=en-glb
  - https://jvn.jp/en/vu/JVNVU90448293/
rules:
  - title: Detect V-SFT Spawning Suspicious Processes
    description: Detects V-SFT potentially spawning child processes after CVE-2026-32928 exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect V-SFT Opening Malicious V7 File
    description: Detects V-SFT opening a V7 file from a suspicious location, potentially related to CVE-2026-32928 exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

V-SFT versions 6.2.10.0 and earlier are vulnerable to a stack-based buffer overflow (CVE-2026-32928) located in the VS6ComFile!CSaveData::_conv_AnimationItem function. This vulnerability is triggered when the software processes a specially crafted V7 file. Successful exploitation of this vulnerability can lead to arbitrary code execution within the context of the application. Given the potential for complete system compromise, organizations using affected versions of V-SFT should take immediate…
