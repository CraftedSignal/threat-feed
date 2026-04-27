---
title: CoolerControl Command Injection Vulnerability (CVE-2026-5208)
slug: 2026-04-coolercontrol-cmd-injection
description: CoolerControl/coolercontrold versions before 4.0.0 are vulnerable to command injection, allowing authenticated attackers with high privileges to execute arbitrary code as root by injecting bash commands into alert names.
date: "2026-04-08T12:16:22Z"
severities:
  - critical
tags:
  - command-injection
  - privilege-escalation
  - coolercontrol
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
cves:
  - id: CVE-2026-5208
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5208
  - https://gitlab.com/coolercontrol/coolercontrol/-/blob/3.1.0/coolercontrold/src/alerts.rs?ref_type=tags#L576
  - https://gitlab.com/coolercontrol/coolercontrol/-/releases/4.0.0
rules:
  - title: Detect Suspicious Alert Creation
    description: Detects creation of alerts with potentially malicious commands in the name field.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious Process Spawned by coolercontrold
    description: Detects suspicious processes spawned by coolercontrold, indicating potential command injection.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CoolerControl/coolercontrold, a system monitoring and management tool, is susceptible to a command injection vulnerability (CVE-2026-5208) in versions prior to 4.0.0. The vulnerability stems from insufficient sanitization of user-supplied input used to create alert names. An authenticated attacker with high privileges can inject arbitrary bash commands into the alert name field. Due to the application's execution context, these injected commands are executed with root privileges, potentially…
