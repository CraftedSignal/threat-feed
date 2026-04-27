---
title: MiroFish Command Injection Vulnerability (CVE-2026-7058)
slug: 2024-01-03-mirofish-command-injection
description: A command injection vulnerability exists in 666ghj MiroFish version 0.1.2 via the SimulationIPCClient.send_command function, allowing remote attackers to execute arbitrary commands.
date: "2024-01-03T12:00:00Z"
severities:
  - high
tags:
  - command-injection
  - vulnerability
  - ipc
products:
  - MiroFish
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1569
    technique_name: System Services
cves:
  - id: CVE-2026-7058
    cvss: 7.3
    epss: 0.01039
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7058
rules:
  - title: Detect MiroFish Command Injection Attempt via URL
    description: Detects potential attempts to exploit the MiroFish command injection vulnerability by monitoring requests to the vulnerable endpoint.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1569.002
    data_sources:
      - webserver
      - linux
  - title: Detect MiroFish Command Injection Attempt via POST Data
    description: Detects potential attempts to exploit the MiroFish command injection vulnerability by monitoring POST requests to the vulnerable endpoint with suspicious characters in the request body.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1569.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A command injection vulnerability, identified as CVE-2026-7058, affects 666ghj MiroFish up to version 0.1.2. The vulnerability resides in the `SimulationIPCClient.send_command` function within the `backend/app/services/simulation_ipc.py` file, specifically within the Inter-Process Communication component. This flaw allows a remote attacker to inject and execute arbitrary commands on the system. Public disclosure of the exploit exists, increasing the risk of exploitation. The vendor was…
