---
title: Google Chrome Prerender Use-After-Free Vulnerability (CVE-2026-6299)
slug: 2026-04-chrome-use-after-free
description: A use-after-free vulnerability (CVE-2026-6299) in Google Chrome's Prerender component before version 147.0.7727.101 allows a remote attacker to execute arbitrary code by crafting a malicious HTML page.
date: "2026-04-16T12:00:00Z"
severities:
  - critical
tags:
  - CVE-2026-6299
  - use-after-free
  - google-chrome
  - code-execution
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-6299
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6299
  - https://chromereleases.googleblog.com/2026/04/stable-channel-update-for-desktop_15.html
  - https://issues.chromium.org/issues/497053588
rules:
  - title: Detect Chrome Use-After-Free Exploit Attempt
    description: Detects attempts to exploit use-after-free vulnerabilities in Chrome by monitoring for suspicious patterns in web server logs.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.007
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect Chrome Suspicious Process Spawning
    description: Detects suspicious process spawning from Chrome browser, indicating potential exploitation.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1059.003
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-6299 is a critical security vulnerability affecting Google Chrome versions prior to 147.0.7727.101. This use-after-free vulnerability resides within the Prerender component, which is responsible for preloading web pages to improve browsing speed. A remote attacker can exploit this vulnerability by crafting a malicious HTML page and enticing a user to open it in a vulnerable version of Chrome. Successful exploitation leads to arbitrary code execution within the context of the user…
