---
title: Google Chrome Font Integer Overflow Vulnerability (CVE-2026-4679)
slug: 2026-03-chrome-font-overflow
description: A remote attacker can perform an out-of-bounds memory write on Google Chrome by exploiting an integer overflow in the Fonts component via a crafted HTML page in versions prior to 146.0.7680.165.
date: "2026-03-24T01:17:03Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-4679
  - chrome
  - integer-overflow
  - memory-corruption
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204.002
    technique_name: 'User Execution: Malicious File'
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4679
  - https://chromereleases.googleblog.com/2026/03/stable-channel-update-for-desktop_23.html
  - https://issues.chromium.org/issues/491516670
rules:
  - title: Detect Chrome Font Integer Overflow Attempt
    description: Detects potential attempts to exploit the Chrome font integer overflow vulnerability (CVE-2026-4679) by monitoring process creations that load font libraries after suspicious network activity.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Font File Download
    description: Detects the download of font files from unusual sources, which could be indicative of an attempt to deliver a malicious font for exploitation.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-4679 is an integer overflow vulnerability affecting the Fonts component in Google Chrome versions prior to 146.0.7680.165. A remote attacker can exploit this vulnerability by crafting a malicious HTML page that, when rendered by a vulnerable Chrome browser, triggers an integer overflow condition, leading to an out-of-bounds memory write. This vulnerability exists because of insufficient validation when handling font data. Successful exploitation could lead to arbitrary code execution…
