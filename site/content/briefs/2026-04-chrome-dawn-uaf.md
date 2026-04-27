---
title: Google Chrome Dawn Use-After-Free Vulnerability (CVE-2026-6310)
slug: 2026-04-chrome-dawn-uaf
description: A use-after-free vulnerability (CVE-2026-6310) in Google Chrome's Dawn component allows a remote attacker, having compromised the renderer process, to potentially execute a sandbox escape via a specially crafted HTML page.
date: "2026-04-16T12:00:00Z"
severities:
  - high
tags:
  - cve-2026-6310
  - use-after-free
  - sandbox escape
  - google chrome
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-6310
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6310
  - https://chromereleases.googleblog.com/2026/04/stable-channel-update-for-desktop_15.html
  - https://issues.chromium.org/issues/497969820
ioc_counts:
  email: 1
rules:
  - title: Detect Chrome Renderer Process Spawning Unusual Processes
    description: Detects unusual processes spawned by the Chrome renderer process, which may indicate a sandbox escape attempt following exploitation of CVE-2026-6310.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Chrome Renderer Process Network Connection to Non-Standard Ports
    description: Detects network connections initiated from the Chrome renderer process to non-standard ports, potentially indicating command and control activity after exploiting CVE-2026-6310.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-6310 is a high-severity vulnerability affecting Google Chrome versions prior to 147.0.7727.101. The vulnerability lies within the Dawn component, a library used for interacting with the WebGPU API. An attacker who has already compromised the Chrome renderer process can exploit this use-after-free vulnerability to potentially escape the Chrome sandbox. Successful exploitation requires the attacker to craft a malicious HTML page that triggers the vulnerability in Dawn, enabling them to…
