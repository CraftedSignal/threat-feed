---
title: File Browser Stored XSS via Crafted EPUB File
slug: 2024-07-filebrowser-xss
description: File Browser version 2.62.1 and earlier is vulnerable to stored cross-site scripting (XSS) via crafted EPUB files, allowing attackers to execute arbitrary JavaScript in a victim's browser by exploiting the application's misconfigured iframe sandbox and stealing sensitive information like JWT tokens.
date: "2026-03-31T23:44:36Z"
severities:
  - high
tags:
  - filebrowser
  - xss
  - epub
  - cve-2026-34529
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Local Account
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
cves:
  - id: CVE-2024-35236
    cvss: 4.8
    epss: 0.01425
references:
  - https://github.com/advisories/GHSA-5vpr-4fgw-f69h
ioc_counts:
  url: 2
rules:
  - title: Detect File Browser EPUB XSS Attempt
    description: Detects attempts to exploit the File Browser EPUB XSS vulnerability by monitoring for network connections to ifconfig.me from the File Browser process, which is used to obtain the victim's IP address.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
      - T1190
    data_sources:
      - network_connection
      - windows
  - title: Detect File Browser JWT Exfiltration
    description: Detects potential JWT token exfiltration attempts in File Browser by monitoring for network connections to attacker.example with the stolen parameter.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1041
      - T1190
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

File Browser, a web-based file management application, is susceptible to stored XSS attacks in versions 2.62.1 and earlier. The vulnerability stems from the application's EPUB preview functionality, which allows scripted content (`allowScriptedContent: true`) to execute within an iframe.  The iframe's sandbox is misconfigured, including both `allow-scripts` and `allow-same-origin`, effectively bypassing the intended security restrictions. An attacker can upload a specially crafted EPUB file…
