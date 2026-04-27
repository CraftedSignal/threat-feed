---
title: Google Chrome V8 Type Confusion Vulnerability (CVE-2026-6363)
slug: 2026-04-chrome-v8-type-confusion
description: A type confusion vulnerability (CVE-2026-6363) in Google Chrome's V8 JavaScript engine before version 147.0.7727.101 allows a remote attacker to potentially perform out-of-bounds memory access via a crafted HTML page.
date: "2026-04-16T12:00:00Z"
severities:
  - medium
tags:
  - cve-2026-6363
  - chrome
  - v8
  - type confusion
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Information Discovery
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-6363
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6363
  - https://chromereleases.googleblog.com/2026/04/stable-channel-update-for-desktop_15.html
  - https://issues.chromium.org/issues/495751197
rules:
  - title: Detect Suspicious Chrome Process Memory Access
    description: Detects suspicious memory access patterns within Chrome processes, potentially indicating exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - process_creation
      - windows
  - title: Detect Chrome Launching Suspicious Child Processes
    description: Detects Chrome processes launching unusual or potentially malicious child processes.
    platform: sigma
    severity: low
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-6363 is a type confusion vulnerability affecting the V8 JavaScript engine within Google Chrome. This vulnerability resides in versions prior to 147.0.7727.101. A remote attacker could exploit this flaw by crafting a malicious HTML page designed to trigger the type confusion, leading to an out-of-bounds memory access. The Chromium security team rated this vulnerability as having medium severity. Successful exploitation could allow an attacker to potentially execute arbitrary code within…
