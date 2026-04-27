---
title: GitPilot-MCP Command Injection Vulnerability (CVE-2026-6980)
slug: 2024-01-02-gitpilot-command-injection
description: A command injection vulnerability (CVE-2026-6980) in Divyanshu-hash GitPilot-MCP up to version 9ed9f153ba4158a2ad230ee4871b25130da29ffd allows remote attackers to execute arbitrary commands by manipulating the 'command' argument in the repo_path function of main.py, and public exploit code is available.
date: "2024-01-02T12:00:00Z"
severities:
  - high
tags:
  - command-injection
  - web-application
  - cve
vendors:
  - Divyanshu-hash
products:
  - GitPilot-MCP
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1569
    technique_name: System Services
cves:
  - id: CVE-2026-6980
    cvss: 7.3
    epss: 0.01021
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6980
rules:
  - title: GitPilot-MCP Command Injection Attempt
    description: Detects attempts to exploit the command injection vulnerability (CVE-2026-6980) in GitPilot-MCP by looking for suspicious characters in the request URI.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1569.002
    data_sources:
      - webserver
      - linux
  - title: GitPilot-MCP Suspicious Child Process
    description: Detects potentially malicious child processes spawned by the GitPilot-MCP application.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1569.002
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A command injection vulnerability, identified as CVE-2026-6980, has been discovered in the GitPilot-MCP project by Divyanshu-hash. The vulnerability affects versions up to 9ed9f153ba4158a2ad230ee4871b25130da29ffd. Attackers can exploit this flaw by manipulating the `command` argument passed to the `repo_path` function within the `main.py` file. This manipulation enables remote command execution on the affected system. Publicly available exploit code exists, increasing the risk of exploitation…
