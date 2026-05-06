---
title: PraisonAI OS Command Injection Vulnerability (CVE-2026-40088)
slug: 2026-04-praisonai-command-injection
description: PraisonAI versions prior to 4.5.121 are vulnerable to OS command injection, allowing attackers to execute arbitrary shell commands via user-controlled input in agent workflows, YAML definitions, and LLM-generated tool calls.
date: "2026-04-09T20:16:27Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve-2026-40088
  - command-injection
  - praisonai
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-40088
    cvss: 9.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40088
  - https://github.com/MervinPraison/PraisonAI/releases/tag/v4.5.121
  - https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-2763-cj5r-c79m
rules:
  - title: Detect PraisonAI Command Injection Attempts via Workflow
    description: Detects command injection attempts in PraisonAI workflows by monitoring for shell metacharacters in process creation events originating from the PraisonAI process.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect PraisonAI Command Injection Attempts via YAML
    description: Detects command injection attempts in PraisonAI YAML definitions by monitoring for shell metacharacters in the YAML parser process.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

PraisonAI, a multi-agent teams system, is susceptible to OS command injection in versions prior to 4.5.121. The vulnerability, identified as CVE-2026-40088, stems from the `execute_command` function and workflow shell execution, which improperly handles user-controlled input. Attackers can inject arbitrary shell commands through shell metacharacters via agent workflows, YAML definitions, and LLM-generated tool calls. This can lead to complete system compromise. It is critical to upgrade to version 4.5.121 or later to remediate this vulnerability. The CVSS v3.1 base score for this vulnerability is 9.6, indicating a critical severity.

## Attack Chain

1.  An attacker crafts a malicious YAML definition or workflow for PraisonAI.
2.  This crafted input contains shell metacharacters designed to inject arbitrary commands.
3.  The user (victim) imports or executes the attacker-supplied YAML or workflow within PraisonAI.
4.  The `execute_command` function processes the input without proper sanitization.
5.  The injected shell commands are executed by the underlying operating system.
6.  The attacker gains arbitrary code execution privileges on the PraisonAI server.
7.  The attacker can then perform lateral movement, data exfiltration, or system compromise.
8.  The attacker can further leverage the compromised system to target other systems within the network.

## Impact

Successful exploitation of CVE-2026-40088 allows an attacker to execute arbitrary commands on the PraisonAI server. This can lead to complete system compromise, data exfiltration, and potential lateral movement within the network. The severity of this vulnerability is rated as critical with a CVSS v3.1 score of 9.6. This could affect any organization using PraisonAI versions prior to 4.5.121.

## Recommendation

*   Immediately upgrade PraisonAI to version 4.5.121 or later to patch CVE-2026-40088.
*   Implement input validation and sanitization for all user-supplied data processed by the `execute_command` function.
*   Monitor PraisonAI logs for suspicious command execution patterns after upgrading.
*   Deploy the Sigma rules provided below to detect potential exploitation attempts.
*   Review and restrict permissions of the PraisonAI service account to minimize the impact of successful command injection.
