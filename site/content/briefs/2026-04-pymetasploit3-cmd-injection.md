---
title: Pymetasploit3 Command Injection Vulnerability (CVE-2026-5463)
slug: 2026-04-pymetasploit3-cmd-injection
description: A command injection vulnerability in pymetasploit3 versions up to 1.0.6 allows attackers to inject newline characters into module options, leading to arbitrary command execution within Metasploit sessions.
date: "2026-04-03T05:16:24Z"
severities:
  - high
tags:
  - command-injection
  - metasploit
  - pymetasploit3
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
cves:
  - id: CVE-2026-5463
    cvss: 8.6
    epss: 0.01784
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5463
  - https://github.com/DanMcInerney/pymetasploit3
  - https://pypi.org/project/pymetasploit3/
rules:
  - title: Detect Newline Character Injection in pymetasploit3 Module Arguments
    description: Detects attempts to inject newline characters into pymetasploit3 module arguments, potentially leading to command injection (CVE-2026-5463).
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious pymetasploit3 Process Execution with Network Activity
    description: Detects pymetasploit3 processes that initiate network connections, potentially indicating module execution.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

A command injection vulnerability, identified as CVE-2026-5463, affects pymetasploit3 versions up to 1.0.6. This flaw allows an attacker to inject newline characters into module options like RHOSTS when using the `console.run_module_with_output()` function. By exploiting this, attackers can break the intended command structure and inject malicious commands, causing the Metasploit console to execute unintended actions. Successful exploitation can lead to arbitrary command execution, potentially…
