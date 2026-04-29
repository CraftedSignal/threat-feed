---
title: PraisonAI Remote Code Execution via Malicious Workflow YAML
slug: 2024-01-03-praisonai-rce
description: 'PraisonAI is vulnerable to remote code execution; loading untrusted YAML files with `type: job` can lead to arbitrary host command execution, potentially enabling full system compromise.'
date: "2026-04-10T19:32:48Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - praisonai
  - rce
  - yaml
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-vc46-vw85-3wvm
iocs:
  - type: filename
    value: exploit.yaml
  - type: filename
    value: pwned.txt
ioc_counts:
  filename: 2
rules:
  - title: Detect PraisonAI Workflow Execution with Suspicious YAML
    description: Detects the execution of praisonai workflow commands potentially triggered by malicious YAML files
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious File Creation by Python within PraisonAI Workflow
    description: Detects file creation events potentially originating from Python code executed within a PraisonAI workflow, indicative of malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - file_event
      - linux
rules_count: 2
---

PraisonAI is vulnerable to remote code execution via specially crafted YAML files. The vulnerability stems from the `praisonai workflow run <file.yaml>` command, which, when processing YAML files with `type: job`, executes steps through the `JobWorkflowExecutor` class in `job_workflow.py`. This execution path supports shell command execution via `subprocess.run()`, inline Python execution via `exec()`, and arbitrary Python script execution. An attacker can leverage this to inject malicious code into a YAML file, such as `exploit.yaml`, to achieve arbitrary host command execution. Versions of `pip/praisonaiagents` up to and including 1.5.139 and `pip/PraisonAI` up to and including 4.5.138 are affected. This is especially critical in CI/CD environments or shared deployment contexts where untrusted YAML files may be processed.

## Attack Chain

1. An attacker crafts a malicious YAML file (e.g., `exploit.yaml`) containing commands to be executed.
2. The attacker gains access to a system where PraisonAI is installed and can execute the `praisonai` command.
3. The attacker executes the command `praisonai workflow run exploit.yaml`, pointing to the malicious YAML file.
4. PraisonAI parses the YAML file and identifies the `type: job` directive.
5. The `JobWorkflowExecutor` class in `job_workflow.py` is invoked to process the workflow steps.
6. Within the workflow steps, commands specified using `run:`, `script:`, or `python:` directives are executed. Specifically, `_exec_shell()` executes shell commands, `_exec_inline_python()` executes inline Python, and `_exec_python_script()` executes Python scripts.
7. The malicious code executes, performing actions such as writing files (e.g., `pwned.txt`) or executing arbitrary system commands.
8. The attacker achieves arbitrary code execution on the host system, leading to potential system compromise.

## Impact

Successful exploitation allows a remote or local attacker to execute arbitrary host commands and code. This can lead to full system compromise, including data theft, modification, or destruction. In CI/CD or shared deployment contexts, this could impact multiple systems or applications. The reporter marked this as a critical severity vulnerability.

## Recommendation

*   Upgrade `pip/praisonaiagents` and `pip/PraisonAI` to versions greater than 1.5.139 and 4.5.138, respectively, to patch the vulnerability as stated in the overview.
*   Implement strict input validation and sanitization for all YAML files processed by PraisonAI, paying close attention to the `type: job` directive to prevent execution of arbitrary commands and code.
*   Deploy the Sigma rule "Detect PraisonAI Workflow Execution with Suspicious YAML" to your SIEM to detect potential exploitation attempts, based on log source `process_creation`.
