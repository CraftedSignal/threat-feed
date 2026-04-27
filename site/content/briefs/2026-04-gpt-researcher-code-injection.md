---
title: GPT Researcher Code Injection Vulnerability (CVE-2026-5631)
slug: 2026-04-gpt-researcher-code-injection
description: A remote code injection vulnerability exists in assafelovic gpt-researcher versions up to 3.4.3 due to improper handling of the 'args' argument in the extract_command_data function, potentially allowing attackers to execute arbitrary code.
date: "2026-04-06T07:16:01Z"
severities:
  - high
tags:
  - code-injection
  - vulnerability
  - gpt-researcher
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Code Injection
cves:
  - id: CVE-2026-5631
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5631
  - https://github.com/assafelovic/gpt-researcher/
  - https://vuldb.com/vuln/355419
rules:
  - title: Detect GPT Researcher Code Injection Attempt via ws Endpoint
    description: Detects potential code injection attempts targeting the extract_command_data function in GPT Researcher via suspicious requests to the ws Endpoint.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1505.003
    data_sources:
      - webserver
      - linux
  - title: Detect GPT Researcher Process Spawning from Web Server
    description: Detects unexpected process spawning from the web server process after CVE-2026-5631.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A code injection vulnerability, identified as CVE-2026-5631, affects assafelovic gpt-researcher up to version 3.4.3. The vulnerability resides in the `extract_command_data` function within the `backend/server/server_utils.py` file, specifically in the `ws Endpoint` component. By manipulating the `args` argument, a remote attacker can inject and execute arbitrary code on the affected system. Public exploit code is available, increasing the risk of exploitation. The maintainers of the…
