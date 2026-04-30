---
title: Google Chrome Out-of-Bounds Read Vulnerability (CVE-2026-4674)
slug: 2026-03-chrome-oob-read
description: A remote attacker can exploit an out-of-bounds read vulnerability (CVE-2026-4674) in Google Chrome versions prior to 146.0.7680.165 to achieve out-of-bounds memory access via a crafted HTML page, impacting confidentiality, integrity, and availability.
date: "2026-03-24T01:17:02Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve
  - out-of-bounds read
  - chrome
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Information Discovery
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4674
  - https://chromereleases.googleblog.com/2026/03/stable-channel-update-for-desktop_23.html
  - https://issues.chromium.org/issues/488188166
ioc_counts:
  email: 1
  url: 1
rules:
  - title: Detect Suspicious Chrome Process Accessing Network
    description: Detects network connections initiated by the Chrome process, which may indicate exploitation of CVE-2026-4674 leading to arbitrary code execution and command and control.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Chrome Launching Suspicious Child Processes
    description: Detects the launch of suspicious processes from Chrome, which can indicate exploitation leading to code execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-4674 is an out-of-bounds read vulnerability affecting Google Chrome versions prior to 146.0.7680.165. This vulnerability resides in the CSS processing engine of Chrome. A remote attacker can exploit this vulnerability by crafting a malicious HTML page that, when opened in a vulnerable version of Chrome, triggers an out-of-bounds read. The successful exploitation of this vulnerability allows the attacker to read sensitive information from the browser's memory, potentially leading to…
