---
title: Google Chrome Proxy Use-After-Free Vulnerability (CVE-2026-6297)
slug: 2026-04-chrome-use-after-free
description: CVE-2026-6297 is a critical use-after-free vulnerability in the Proxy component of Google Chrome before version 147.0.7727.101, enabling a privileged network attacker to potentially achieve sandbox escape via a crafted HTML page.
date: "2026-04-15T20:16:38Z"
severities:
  - critical
tags:
  - cve
  - use-after-free
  - chrome
  - sandbox escape
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-6297
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6297
  - https://chromereleases.googleblog.com/2026/04/stable-channel-update-for-desktop_15.html
  - https://issues.chromium.org/issues/493628982
rules:
  - title: Detect Chrome Sandbox Escape via Crafted HTML
    description: Detects potential sandbox escape attempts in Google Chrome by monitoring for specific HTML elements or attributes often used in exploit code.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1027
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Chrome Process Memory Access
    description: Detects potential sandbox escape attempts in Google Chrome by monitoring for process accessing Chrome's process memory
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1027
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-6297 is a critical security flaw affecting Google Chrome users. The vulnerability, a use-after-free issue within the Proxy component, exists in versions prior to 147.0.7727.101. Successfully exploiting this vulnerability would allow an attacker positioned in a privileged network location to potentially break out of Chrome's sandbox. The attack vector involves a specially crafted HTML page delivered to the victim. This is a critical vulnerability because a successful exploit could lead…
