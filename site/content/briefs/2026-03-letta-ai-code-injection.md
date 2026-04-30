---
title: letta-ai letta 0.16.4 Remote Code Injection Vulnerability (CVE-2026-4965)
slug: 2026-03-letta-ai-code-injection
description: letta-ai letta version 0.16.4 contains a remote code injection vulnerability (CVE-2026-4965) in the resolve_type function of ast_parsers.py, stemming from improper neutralization of directives in dynamically evaluated code, allowing unauthenticated remote attackers to execute arbitrary code.
date: "2026-03-27T18:16:06Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - CVE-2026-4965
  - code-injection
  - letta-ai
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4965
rules:
  - title: Detect Suspicious Process Spawned By Web Application
    description: Detects processes spawned by web applications that are not typically associated with normal operation, which may indicate code injection or command execution vulnerabilities.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Web Server Request with Suspicious Parameters
    description: Detects web server requests to specific endpoints with parameters indicative of code injection attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

letta-ai letta version 0.16.4 is vulnerable to remote code injection due to improper neutralization of directives in dynamically evaluated code within the `resolve_type` function of `letta/functions/ast_parsers.py`. This vulnerability, identified as CVE-2026-4965, is a consequence of an incomplete fix for CVE-2025-6101. An unauthenticated, remote attacker can exploit this flaw by manipulating input to inject arbitrary code. The exploit is publicly available, increasing the risk of widespread…
