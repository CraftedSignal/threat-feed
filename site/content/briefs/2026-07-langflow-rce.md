---
title: Unauthenticated Remote Code Execution in IBM Langflow OSS
slug: 2026-07-langflow-rce
description: IBM Langflow OSS versions 1.0.0 through 1.10.1 are susceptible to unauthenticated remote code execution due to improper sanitization of environment variables in the MCP stdio launcher.
date: "2026-07-30T17:29:49Z"
lastmod: "2026-07-30T19:30:32Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - remote-code-execution
  - cve-2026-12940
  - ibm
  - langflow
  - code-injection
  - vulnerability
  - rce
vendors:
  - IBM
products:
  - Langflow OSS (1.0.0 - 1.10.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: IBM Langflow OSS 1.0.0 through 1.10.1 are vulnerable to unauthenticated remote code execution via environment variable injection in the MCP (Model Context Protocol) stdio launcher.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
    evidence: The vulnerability exists in src/lfx/src/lfx/base/mcp/util.py where the DANGEROUS_ENV_VARS blocklist fails to include SHELLOPTS , BASHOPTS , and PS4 environment variables.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: IBM Langflow OSS 1.0.0 through 1.10.1 contains an improper input validation vulnerability in the PythonREPL sandbox implementation.
    confidence_band: high
cves:
  - id: CVE-2026-12940
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-12940
  - https://www.ibm.com/support/pages/node/7279995
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13435
  - https://www.ibm.com/support/pages/node/7279987
updates:
  - at: "2026-07-30T19:30:32Z"
    level: L2
    summary: 'merged source coverage: Improper Input Validation Vulnerability in IBM Langflow OSS PythonREPL'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-13435
---

IBM Langflow OSS versions 1.0.0 through 1.10.1 contain a critical vulnerability (CVE-2026-12940) in the Model Context Protocol (MCP) stdio launcher. The flaw originates in 'src/lfx/src/lfx/base/mcp/util.py', where the 'DANGEROUS_ENV_VARS' blocklist fails to filter sensitive environment variables, specifically 'SHELLOPTS', 'BASHOPTS', and 'PS4'. 

An unauthenticated remote attacker can exploit this oversight by injecting these environment variables into the application's process execution flow. By manipulating these variables, an attacker can influence shell behavior to execute arbitrary OS commands when the launcher initiates subprocesses. Because the vulnerability allows for unauthenticated interaction with the MCP interface, it presents a significant risk for server compromise in environments hosting Langflow instances.

## Attack Chain

1. Attacker identifies a target server hosting IBM Langflow OSS (versions 1.0.0 through 1.10.1).
2. Attacker interacts with the unauthenticated Model Context Protocol (MCP) endpoint exposed by the application.
3. Attacker crafts a malicious request intended to trigger the stdio launcher process.
4. Attacker injects forbidden environment variables ('SHELLOPTS', 'BASHOPTS', or 'PS4') into the application's request parameters.
5. The 'DANGEROUS_ENV_VARS' blocklist in the vulnerable 'util.py' script fails to filter the injected variables.
6. The application initializes a subprocess using the influenced environment settings.
7. The shell interpreter executes arbitrary commands defined via the injected variables, resulting in remote code execution.

## Impact

Successful exploitation of this vulnerability leads to unauthenticated remote code execution on the underlying host. This grants an attacker the ability to execute arbitrary commands, potentially leading to total system compromise, data exfiltration, or deployment of further payloads. Given the nature of the application as an orchestration tool for AI workflows, attackers could potentially manipulate sensitive LLM inputs or access internal network resources from the compromised container or host.

## Recommendation

* Immediately upgrade IBM Langflow OSS to a patched version beyond 1.10.1 to mitigate CVE-2026-12940.
* Review logs for unusual process spawning activities originating from the Langflow process user.
* Restrict network access to the Langflow MCP management interface to trusted internal segments only, as the vulnerability does not require authentication.
* Implement strict environment variable monitoring and container security policies to detect attempts to inject shell-specific variables into application subprocesses.
