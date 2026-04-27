---
title: Modelscope Agentscope Code Injection Vulnerability (CVE-2026-6603)
slug: 2026-04-agentscope-code-injection
description: A code injection vulnerability exists in modelscope agentscope up to version 1.0.18, specifically affecting the execute_python_code/execute_shell_command functions, allowing for remote code execution.
date: "2026-04-20T05:16:15Z"
severities:
  - high
tags:
  - code-injection
  - remote-code-execution
  - agentscope
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6603
  - https://gist.github.com/YLChen-007/c084d69aaeda6729f3988603f2b0ce6e
  - https://vuldb.com/vuln/358238
rules:
  - title: Detect Suspicious Process Execution from Agentscope
    description: Detects process execution originating from the agentscope application server, which may indicate exploitation of CVE-2026-6603.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Malicious Requests to Agentscope Code Execution Endpoints
    description: Detects suspicious HTTP requests targeting the execute_python_code or execute_shell_command endpoints in Agentscope, indicating potential code injection attempts (CVE-2026-6603).
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical code injection vulnerability, identified as CVE-2026-6603, affects modelscope agentscope versions up to 1.0.18. The vulnerability resides within the `execute_python_code` and `execute_shell_command` functions in the `src/AgentScope/tool/_coding/_python.py` file. This flaw allows an attacker to inject arbitrary code, leading to potential remote code execution on the affected system. A public exploit is available, increasing the risk of widespread exploitation. The vendor was contacted…
