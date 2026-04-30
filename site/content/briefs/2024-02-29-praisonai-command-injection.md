---
title: PraisonAI Vulnerable to OS Command Injection
slug: 2024-02-29-praisonai-command-injection
description: PraisonAI is vulnerable to OS command injection due to the use of `subprocess.run()` with `shell=True` on user-controlled inputs, allowing attackers to inject arbitrary shell commands and potentially leading to sensitive data exfiltration or system compromise in versions prior to 4.5.121.
date: "2026-04-08T21:52:10Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - command-injection
  - rce
  - praisonai
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-2763-cj5r-c79m
iocs:
  - type: domain
    value: attacker.com
ioc_counts:
  domain: 1
rules:
  - title: Detect PraisonAI Command Injection via Workflow
    description: Detects command injection attempts in PraisonAI by monitoring process creations that execute PraisonAI with suspicious shell commands in workflow files.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect PraisonAI Command Injection via Agent Configuration
    description: Detects command injection attempts in PraisonAI by monitoring process creations with shell commands in agent configuration files.
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

PraisonAI versions prior to 4.5.121 are susceptible to OS command injection. The vulnerability stems from the application's use of `subprocess.run()` with the `shell=True` parameter when executing commands derived from various user-controlled inputs. These inputs include YAML workflow definitions, agent configuration files (agents.yaml), LLM-generated tool call parameters, and recipe step configurations. This configuration allows an attacker to inject arbitrary shell commands through shell metacharacters, leading to potential remote code execution and system compromise. This vulnerability is particularly concerning in automated environments like CI/CD pipelines or agent workflows, where unintended command execution can occur without direct user awareness.

## Attack Chain

1.  An attacker crafts a malicious YAML workflow definition or modifies an existing one, injecting shell metacharacters into the `target` field of a `shell` step.
2.  Alternatively, the attacker modifies the `agents.yaml` file, injecting malicious commands into the `shell_command` field of an agent task.
3.  The attacker triggers the execution of the crafted YAML workflow or loads the modified `agents.yaml` file using PraisonAI's command-line interface.
4.  PraisonAI parses the YAML file and extracts the attacker-controlled command string.
5.  The application then passes this command string to `subprocess.run()` with `shell=True`, allowing the shell to interpret the injected metacharacters.
6.  The shell executes the attacker's injected commands, potentially performing actions like reading sensitive files, exfiltrating data, or modifying system configurations.
7.  If using agent mode, an attacker can influence the LLM's context to generate malicious tool calls including shell commands.
8.  The attacker achieves arbitrary code execution with the privileges of the PraisonAI process, leading to system compromise or data breach.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary shell commands on the affected system. This can lead to a variety of negative consequences, including unauthorized access to sensitive data (such as configuration files, credentials, or user data), modification or deletion of system files, and potentially full system compromise. In automated environments like CI/CD pipelines, this vulnerability could allow an attacker to inject malicious code into software builds, leading to supply chain attacks. The vulnerability affects versions of PraisonAI prior to 4.5.121.

## Recommendation

*   Deploy the Sigma rule "Detect PraisonAI Command Injection via Workflow" to identify attempts to exploit this vulnerability through malicious YAML workflow definitions (logsource: `process_creation`).
*   Deploy the Sigma rule "Detect PraisonAI Command Injection via Agent Configuration" to identify attempts to exploit this vulnerability through malicious agent configurations (logsource: `process_creation`).
*   Block the C2 domain `attacker.com` listed in the IOC table at the DNS resolver to prevent data exfiltration and command-and-control communication (type: `domain`, value: `attacker.com`).
*   Upgrade PraisonAI to version 4.5.121 or later to patch this vulnerability (Affected Packages).
