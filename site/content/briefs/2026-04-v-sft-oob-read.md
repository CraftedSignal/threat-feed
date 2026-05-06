---
title: V-SFT Out-of-Bounds Read Vulnerability (CVE-2026-32926)
slug: 2026-04-v-sft-oob-read
description: V-SFT versions 6.2.10.0 and prior contain an out-of-bounds read vulnerability in the VS6ComFile!load_link_inf function, allowing for potential information disclosure when opening a crafted V7 file.
date: "2026-04-01T23:17:02Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - cve-2026-32926
  - out-of-bounds read
  - information disclosure
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Software Discovery
  - tactic_id: TA0006
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0006
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
cves:
  - id: CVE-2026-32926
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32926
  - https://felib.fujielectric.co.jp/en/M10010/M20060/document_detail/5d9dd71d-9494-41a4-aa5c-8e6b8b21066b?region=en-glb
  - https://jvn.jp/en/vu/JVNVU90448293/
iocs:
  - type: url
    value: https://felib.fujielectric.co.jp/en/M10010/M20060/document_detail/5d9dd71d-9494-41a4-aa5c-8e6b8b21066b?region=en-glb
  - type: url
    value: https://jvn.jp/en/vu/JVNVU90448293/
ioc_counts:
  url: 2
rules:
  - title: Detect VS-FT opening unusual files
    description: Detects V-SFT opening files with unusual extensions, potentially indicating a crafted V7 file.
    platform: sigma
    severity: low
    tactics:
      - impact
    data_sources:
      - process_creation
      - windows
  - title: Detect V-SFT.exe execution from unusual folders
    description: Detects V-SFT executing from folders other than its typical installation directory, potentially indicating a rogue or tampered executable.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-32926 is an out-of-bounds read vulnerability affecting V-SFT versions 6.2.10.0 and earlier. The vulnerability exists within the `VS6ComFile!load_link_inf` function, which is responsible for processing V7 files. An attacker can exploit this vulnerability by crafting a malicious V7 file that, when opened by a vulnerable V-SFT application, triggers an out-of-bounds read. Successful exploitation could lead to information disclosure, potentially exposing sensitive data to the attacker. This vulnerability was reported and disclosed by JPCERT/CC.

## Attack Chain

1.  Attacker identifies a vulnerable V-SFT version (6.2.10.0 or prior).
2.  Attacker crafts a malicious V7 file designed to trigger the out-of-bounds read in the `VS6ComFile!load_link_inf` function.
3.  Attacker delivers the crafted V7 file to a target user, potentially through social engineering or other means.
4.  The target user opens the malicious V7 file using the vulnerable V-SFT application.
5.  The `VS6ComFile!load_link_inf` function attempts to read data beyond the allocated buffer while processing the crafted V7 file.
6.  This out-of-bounds read allows the attacker to access memory regions outside the intended boundaries.
7.  The attacker gains access to sensitive information stored in the adjacent memory regions due to the information disclosure.
8.  The attacker extracts the disclosed information for malicious purposes.

## Impact

Successful exploitation of CVE-2026-32926 can lead to information disclosure, potentially exposing sensitive data to an attacker. While the specific impact depends on the nature of the disclosed information, it could include intellectual property, configuration details, or other confidential data. The vulnerability affects systems running vulnerable versions of V-SFT.

## Recommendation

*   Upgrade V-SFT to a version greater than 6.2.10.0 to patch CVE-2026-32926.
*   Monitor for attempts to open unusual or suspicious V7 files using V-SFT applications.
*   Implement the Sigma rule `Detect VS-FT opening unusual files` to detect suspicious file access patterns.
*   Review the V-SFT vendor's advisory for additional mitigation guidance ([https://felib.fujielectric.co.jp/en/M10010/M20060/document_detail/5d9dd71d-9494-41a4-aa5c-8e6b8b21066b?region=en-glb](https://felib.fujielectric.co.jp/en/M10010/M20060/document_detail/5d9dd71d-9494-41a4-aa5c-8e6b8b21066b?region=en-glb)).
