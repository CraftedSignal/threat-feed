---
title: Qualcomm IOCTL Memory Corruption Vulnerability (CVE-2026-21375)
slug: 2026-04-qualcomm-ioctl-memory-corruption
description: CVE-2026-21375 is a memory corruption vulnerability in Qualcomm chipsets due to insufficient output buffer size validation during IOCTL processing, potentially leading to arbitrary code execution.
date: "2026-04-06T16:16:30Z"
severities:
  - high
tags:
  - cve-2026-21375
  - qualcomm
  - memory-corruption
  - ioctl
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-21375
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-21375
  - https://docs.qualcomm.com/product/publicresources/securitybulletin/april-2026-bulletin.html
rules:
  - title: Detect Suspicious IOCTL Calls
    description: Detects processes making IOCTL calls that might indicate exploitation attempts.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1070
    data_sources:
      - process_creation
      - windows
  - title: Detect Qualcomm Driver Load
    description: Detects loading of Qualcomm drivers which might be vulnerable.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - image_load
      - windows
rules_count: 2
---

CVE-2026-21375 is a memory corruption vulnerability affecting certain Qualcomm chipsets. The vulnerability stems from a lack of proper size validation when accessing an output buffer during IOCTL (Input/Output Control) processing. This flaw, disclosed in the April 2026 Qualcomm security bulletin, allows a local attacker with limited privileges to potentially overwrite memory, leading to denial of service or even arbitrary code execution. Successful exploitation requires a malicious application…
