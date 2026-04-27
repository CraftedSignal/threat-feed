---
title: V-SFT Out-of-Bounds Read Vulnerability (CVE-2026-32929)
slug: 2026-04-vsft-oob-read
description: V-SFT versions 6.2.10.0 and prior contain an out-of-bounds read vulnerability (CVE-2026-32929) in VS6ComFile!get_macro_mem_COM, where opening a crafted V7 file may lead to information disclosure.
date: "2026-04-01T23:17:03Z"
severities:
  - medium
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

CVE-2026-32929 is an out-of-bounds read vulnerability affecting V-SFT versions 6.2.10.0 and prior. The vulnerability exists within the `VS6ComFile!get_macro_mem_COM` function. An attacker can exploit this vulnerability by crafting a malicious V7 file. When a user opens the crafted V7 file with a vulnerable version of V-SFT, the out-of-bounds read can be triggered, leading to potential information disclosure. This vulnerability was disclosed on April 1, 2026, and poses a risk to users who rely…
