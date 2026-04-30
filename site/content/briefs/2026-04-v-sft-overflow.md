---
title: V-SFT Stack-Based Buffer Overflow Vulnerability (CVE-2026-32928)
slug: 2026-04-v-sft-overflow
description: V-SFT versions 6.2.10.0 and prior are susceptible to a stack-based buffer overflow vulnerability that could allow arbitrary code execution when a malicious V7 file is opened.
date: "2026-04-01T23:17:03Z"
severities:
  - high
type: advisory
types:
  - advisory
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

V-SFT versions 6.2.10.0 and earlier are vulnerable to a stack-based buffer overflow (CVE-2026-32928) located in the VS6ComFile!CSaveData::_conv_AnimationItem function. This vulnerability is triggered when the software processes a specially crafted V7 file. Successful exploitation of this vulnerability can lead to arbitrary code execution within the context of the application. Given the potential for complete system compromise, organizations using affected versions of V-SFT should take immediate steps to mitigate this risk. This vulnerability was reported by JPCERT/CC.

## Attack Chain

1.  Attacker identifies a target using a vulnerable version of V-SFT (<= 6.2.10.0).
2.  Attacker crafts a malicious V7 file designed to trigger the buffer overflow in the `VS6ComFile!CSaveData::_conv_AnimationItem` function.
3.  The attacker delivers the malicious V7 file to the target, potentially through social engineering or other means.
4.  The target user opens the malicious V7 file using the vulnerable V-SFT software.
5.  The `VS6ComFile!CSaveData::_conv_AnimationItem` function processes the V7 file, copying data into a fixed-size buffer on the stack.
6.  The crafted V7 file contains data exceeding the buffer's capacity, causing a buffer overflow.
7.  The overflow overwrites adjacent stack memory, including the return address.
8.  When the `_conv_AnimationItem` function returns, execution is redirected to an attacker-controlled address, allowing arbitrary code execution.

## Impact

Successful exploitation of CVE-2026-32928 allows an attacker to execute arbitrary code on the affected system. This could lead to complete system compromise, data theft, or denial of service. The vulnerability affects any system running V-SFT versions 6.2.10.0 and prior. The severity is rated as high with a CVSS v3.1 score of 7.8.

## Recommendation

*   Apply the patch or upgrade to a non-vulnerable version of V-SFT (later than 6.2.10.0) as provided by the vendor.
*   Monitor process creation events for V-SFT processes spawning child processes or executing unusual commands, using the provided Sigma rule.
*   Implement file integrity monitoring for the V-SFT executable and associated libraries to detect unauthorized modifications.
*   Educate users about the risks of opening files from untrusted sources to mitigate social engineering attacks.
