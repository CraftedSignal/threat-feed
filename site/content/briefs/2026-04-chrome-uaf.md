---
title: Google Chrome CSS Use-After-Free Vulnerability (CVE-2026-6300)
slug: 2026-04-chrome-uaf
description: A use-after-free vulnerability in Google Chrome's CSS engine (CVE-2026-6300) allows a remote attacker to execute arbitrary code within a sandbox by exploiting a crafted HTML page.
date: "2026-04-16T12:00:00Z"
severities:
  - high
tags:
  - cve-2026-6300
  - use-after-free
  - chrome
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2026-6300
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6300
  - https://chromereleases.googleblog.com/2026/04/stable-channel-update-for-desktop_15.html
  - https://issues.chromium.org/issues/491994185
rules:
  - title: Detect Possible Chrome UAF Exploitation
    description: Detects suspicious process creation events potentially related to exploitation of CVE-2026-6300 in Google Chrome.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

CVE-2026-6300 is a use-after-free vulnerability affecting the CSS engine in Google Chrome versions prior to 147.0.7727.101. Successful exploitation allows a remote attacker to execute arbitrary code inside a sandbox environment. The vulnerability is triggered when processing a maliciously crafted HTML page. Google Chrome users who have not updated to version 147.0.7727.101 or later are vulnerable. Given the widespread use of Chrome, this vulnerability poses a significant risk.
