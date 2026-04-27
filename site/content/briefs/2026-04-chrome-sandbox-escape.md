---
title: Google Chrome Sandbox Escape via Uninitialized Use in Accessibility (CVE-2026-6311)
slug: 2026-04-chrome-sandbox-escape
description: A remote attacker who has compromised the renderer process in Google Chrome on Windows prior to version 147.0.7727.101 can potentially perform a sandbox escape via a crafted HTML page due to an uninitialized use in accessibility, as tracked by CVE-2026-6311.
date: "2026-04-16T12:00:00Z"
severities:
  - high
tags:
  - cve-2026-6311
  - chrome
  - sandbox-escape
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-6311
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6311
  - https://chromereleases.googleblog.com/2026/04/stable-channel-update-for-desktop_15.html
  - https://issues.chromium.org/issues/498201025
ioc_counts:
  email: 1
rules:
  - title: Detect Chrome Sandbox Escape via Child Process
    description: Detects suspicious child processes spawned by the Chrome renderer process, indicative of a successful sandbox escape.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Chrome Renderer Process Accessing Sensitive Files
    description: Detects a Chrome renderer process attempting to read or write sensitive files, potentially indicating a sandbox escape.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - windows
rules_count: 2
---

CVE-2026-6311 describes a high-severity vulnerability affecting Google Chrome on Windows. Specifically, an uninitialized use in the Accessibility component exists in versions prior to 147.0.7727.101. This flaw allows a remote attacker, who has already compromised the renderer process, to potentially escape the browser's sandbox environment. The attacker exploits this vulnerability by crafting a malicious HTML page. Successful exploitation allows the attacker to execute code outside of the…
