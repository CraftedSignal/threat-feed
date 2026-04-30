---
title: Google Chrome WebAudio Out-of-Bounds Read Vulnerability (CVE-2026-4677)
slug: 2026-03-chrome-webaudio-oob-read
description: A remote attacker can trigger an out-of-bounds memory read in Google Chrome's WebAudio implementation by crafting a malicious HTML page (CVE-2026-4677), affecting versions prior to 146.0.7680.165.
date: "2026-03-24T01:17:03Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-4677
  - chrome
  - webaudio
  - out-of-bounds read
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4677
  - https://chromereleases.googleblog.com/2026/03/stable-channel-update-for-desktop_23.html
  - https://issues.chromium.org/issues/490533968
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious WebAudio Usage
    description: Detects potentially malicious HTML pages using WebAudio features aggressively, possibly indicative of CVE-2026-4677 exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect Chrome version before patch of CVE-2026-4677
    description: Detects user agent strings indicating a Google Chrome version vulnerable to CVE-2026-4677.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-4677 describes an out-of-bounds memory read vulnerability in the WebAudio component of Google Chrome. Successful exploitation of this vulnerability allows a remote attacker to potentially read sensitive information from the browser's memory. The vulnerability exists in Google Chrome versions prior to 146.0.7680.165. The attack involves crafting a malicious HTML page that, when opened in a vulnerable version of Chrome, triggers the out-of-bounds read in the WebAudio processing. The…
