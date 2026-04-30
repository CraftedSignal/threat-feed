---
title: V-SFT Out-of-Bounds Read Vulnerability (CVE-2026-32929)
slug: 2026-04-vsft-oob-read
description: V-SFT versions 6.2.10.0 and prior contain an out-of-bounds read vulnerability (CVE-2026-32929) in VS6ComFile!get_macro_mem_COM, where opening a crafted V7 file may lead to information disclosure.
date: "2026-04-01T23:17:03Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - cve-2026-32929
  - out-of-bounds read
  - information disclosure
  - v-sft
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
cves:
  - id: CVE-2026-32929
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32929
  - https://felib.fujielectric.co.jp/en/M10010/M20060/document_detail/5d9dd71d-9494-41a4-aa5c-8e6b8b21066b?region=en-glb
  - https://jvn.jp/en/vu/JVNVU90448293/
rules:
  - title: Detect V-SFT V7 File Opening
    description: Detects the opening of .V7 files which could be malicious when opened with vulnerable V-SFT software.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious V-SFT Process Crashes
    description: Detects potential crashes of V-SFT processes, which could be indicative of exploitation attempts targeting CVE-2026-32929.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - application
      - windows
rules_count: 2
---

CVE-2026-32929 is an out-of-bounds read vulnerability affecting V-SFT versions 6.2.10.0 and prior. The vulnerability exists within the `VS6ComFile!get_macro_mem_COM` function. An attacker can exploit this vulnerability by crafting a malicious V7 file. When a user opens the crafted V7 file with a vulnerable version of V-SFT, the out-of-bounds read can be triggered, leading to potential information disclosure. This vulnerability was disclosed on April 1, 2026, and poses a risk to users who rely on V-SFT software for industrial automation and control systems. Organizations should assess their exposure to this vulnerability and take appropriate mitigation steps, including updating to a patched version of V-SFT.

## Attack Chain

1.  Attacker identifies a target using V-SFT versions 6.2.10.0 or prior.
2.  Attacker crafts a malicious V7 file specifically designed to trigger the out-of-bounds read in `VS6ComFile!get_macro_mem_COM`.
3.  Attacker delivers the crafted V7 file to the target, possibly through social engineering or other means.
4.  The target user opens the malicious V7 file using the vulnerable V-SFT software.
5.  V-SFT attempts to parse the crafted V7 file, triggering the `VS6ComFile!get_macro_mem_COM` function.
6.  Due to the malformed structure of the crafted V7 file, the `get_macro_mem_COM` function attempts to read data beyond the allocated buffer.
7.  The out-of-bounds read occurs, potentially disclosing sensitive information from the V-SFT process memory.
8.  The attacker may be able to leverage the disclosed information to further compromise the system or network.

## Impact

Successful exploitation of CVE-2026-32929 can lead to information disclosure. An attacker who successfully exploits this vulnerability may be able to read sensitive data from the memory of the V-SFT process. The disclosed information could potentially include configuration settings, credentials, or other sensitive data that could be used to further compromise the affected system. While the NVD does not yet contain scoring data, JPCERT/CC assigned a base score of 7.8 HIGH.

## Recommendation

*   Upgrade V-SFT to a version that patches CVE-2026-32929 to remediate the vulnerability.
*   Deploy the Sigma rule "Detect V-SFT V7 File Opening" to detect attempts to open V7 files using the vulnerable software.
*   Monitor systems running V-SFT for unexpected behavior or crashes, which could indicate exploitation attempts.
*   Educate users about the risks of opening files from untrusted sources to prevent social engineering attacks.
