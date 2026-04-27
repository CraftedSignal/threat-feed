---
title: Anviz CX2 Lite Authenticated Command Injection Vulnerability (CVE-2026-35682)
slug: 2026-04-anviz-command-injection
description: Anviz CX2 Lite is vulnerable to an authenticated command injection via the filename parameter, leading to arbitrary command execution and root-level access.
date: "2026-04-17T20:16:35Z"
severities:
  - critical
tags:
  - command-injection
  - unauthorized-access
  - iot
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
cves:
  - id: CVE-2026-35682
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35682
  - https://github.com/cisagov/CSAF/blob/develop/csaf_files/OT/white/2026/icsa-26-106-03.json
  - https://www.anviz.com/contact-us.html
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-106-03
rules:
  - title: Detect Anviz CX2 Lite Command Injection Attempt
    description: Detects potential command injection attempts against Anviz CX2 Lite devices by monitoring for suspicious characters in the filename parameter within HTTP requests.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1210
      - T1550.002
    data_sources:
      - webserver
      - linux
  - title: Detect Anviz CX2 Lite Telnetd Startup via Command Injection
    description: Detects telnetd being started, indicating command injection on an Anviz CX2 Lite device.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-35682 describes an authenticated command injection vulnerability in Anviz CX2 Lite devices. An attacker with valid user credentials can inject arbitrary commands into the filename parameter, leading to remote code execution with root privileges. The vulnerability allows an attacker to execute commands like starting telnetd, effectively gaining complete control over the device. This poses a significant risk to organizations using vulnerable Anviz CX2 Lite devices for access control or…
