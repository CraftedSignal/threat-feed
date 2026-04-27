---
title: MetaGPT OS Command Injection Vulnerability (CVE-2026-5972)
slug: 2026-04-metagpt-command-injection
description: A remote command injection vulnerability exists in FoundationAgents MetaGPT <= 0.8.1 via the Terminal.run_command function, allowing unauthenticated attackers to execute arbitrary OS commands.
date: "2026-04-09T20:16:28Z"
severities:
  - critical
tags:
  - CVE-2026-5972
  - command-injection
  - metagpt
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-5972
    cvss: 7.3
    epss: 0.01761
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5972
  - https://github.com/FoundationAgents/MetaGPT/
  - https://github.com/FoundationAgents/MetaGPT/issues/1929
  - https://github.com/paipeline/MetaGPT/commit/d04ffc8dc67903e8b327f78ec121df5e190ffc7b
  - https://vuldb.com/submit/791745
  - https://vuldb.com/vuln/356526
  - https://vuldb.com/vuln/356526/cti
rules:
  - title: Detect Command Execution via MetaGPT
    description: Detects command execution originating from the MetaGPT application, which could indicate command injection exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Outbound Network Connection from MetaGPT
    description: Detects outbound network connections originating from the MetaGPT application to suspicious IP addresses.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

CVE-2026-5972 describes a critical OS command injection vulnerability affecting FoundationAgents MetaGPT versions up to 0.8.1. The vulnerability resides in the `Terminal.run_command` function within the `metagpt/tools/libs/terminal.py` file. This flaw allows remote attackers to inject and execute arbitrary operating system commands on the affected system. The vulnerability is remotely exploitable, meaning that attackers can trigger it over a network without requiring local access. Public…
