---
title: Google Chrome GPU Out-of-Bounds Write Vulnerability (CVE-2026-6314)
slug: 2026-04-chrome-gpu-oob-write
description: Google Chrome versions prior to 147.0.7727.101 are vulnerable to an out-of-bounds write in the GPU process (CVE-2026-6314), allowing a remote attacker with GPU process compromise to potentially perform a sandbox escape via a crafted HTML page.
date: "2026-04-16T12:00:00Z"
severities:
  - high
tags:
  - chrome
  - gpu
  - oob-write
  - sandbox-escape
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-6314
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6314
  - https://chromereleases.googleblog.com/2026/04/stable-channel-update-for-desktop_15.html
  - https://issues.chromium.org/issues/498782145
rules:
  - title: Detect Chrome GPU Process Crash
    description: Detects crashes in the Chrome GPU process, which could be indicative of exploitation attempts against vulnerabilities like CVE-2026-6314.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious HTML Redirection
    description: Detects redirections from normal websites to potential phishing sites or exploit delivery locations
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-6314 is a security vulnerability affecting Google Chrome versions prior to 147.0.7727.101. The vulnerability resides within the GPU process and is classified as an out-of-bounds write. Successful exploitation could allow a remote attacker who has already compromised the GPU process to perform a sandbox escape, potentially gaining broader system access. The vulnerability can be triggered by a crafted HTML page. The Chromium security team has rated this vulnerability as High severity…
