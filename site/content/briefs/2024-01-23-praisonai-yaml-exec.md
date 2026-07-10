---
title: PraisonAI Workflow Engine Vulnerability CVE-2026-40288
slug: 2024-01-23-praisonai-yaml-exec
description: PraisonAI versions before 4.5.139 and praisonaiagents versions before 1.5.140 are vulnerable to arbitrary command execution via untrusted YAML files processed by the workflow engine.
date: "2024-01-23T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - praisonai
  - yaml
  - code-execution
  - cve-2026-40288
vendors:
  - PraisonAI
products:
  - PraisonAI
  - praisonaiagents
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-40288
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40288
rules:
  - title: Detect PraisonAI Workflow YAML Execution
    description: Detects execution of the `praisonai workflow run` command, which can load and execute arbitrary YAML files containing malicious code.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - process_creation
      - linux
  - title: Suspicious Process Execution from PraisonAI
    description: Detects suspicious process execution originating from PraisonAI processes, indicating potential code execution via YAML files.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

PraisonAI, a multi-agent teams system, contains a critical vulnerability (CVE-2026-40288) affecting versions prior to 4.5.139 and praisonaiagents versions prior to 1.5.140. This flaw resides in the workflow engine and allows for arbitrary command and code execution through the use of untrusted YAML files. Specifically, when a YAML file with `type: job` is loaded, the `JobWorkflowExecutor` processes steps like `run`, `script`, and `python` without proper validation or sandboxing. An attacker who can supply or influence a workflow YAML file can execute arbitrary commands on the host system. This poses a significant risk, especially in CI/CD pipelines, shared repositories, or multi-tenant environments where workflow files may be easily accessible or modifiable, leading to complete system compromise.

## Attack Chain

1. An attacker gains the ability to supply or influence a workflow YAML file within a PraisonAI environment. This could involve compromising a shared repository or manipulating a CI/CD pipeline.
2. The attacker crafts a malicious YAML file containing a `type: job` definition.
3. Within the YAML file, the attacker utilizes the `run:` step to inject arbitrary shell commands. Alternatively, they could use the `script:` step for inline Python code execution or the `python:` step to specify an arbitrary Python script.
4. The `praisonai workflow run <file.yaml>` command is executed, loading the malicious YAML file.
5. The `JobWorkflowExecutor` in `job_workflow.py` processes the YAML file.
6. The `action_run()` function in `workflow.py` is called, which in turn executes the injected code via `_exec_shell()`, `_exec_inline_python()`, or `_exec_python_script()` in `job_workflow.py`.
7. The arbitrary command or code is executed on the host system without validation or user confirmation.
8. The attacker achieves full arbitrary command execution, potentially compromising the machine, accessing sensitive data, or obtaining credentials.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary commands on the host system running PraisonAI. This can lead to complete system compromise, including unauthorized access to sensitive data, credential theft, and the potential for lateral movement within the network. The vulnerability is particularly dangerous in environments with shared workflow configurations or multi-tenant deployments. While specific victim counts are unavailable, any system running the vulnerable versions of PraisonAI or praisonaiagents is at risk, potentially leading to significant data breaches and operational disruption.

## Recommendation

*   Immediately upgrade PraisonAI to version 4.5.139 or later and praisonaiagents to version 1.5.140 or later to patch CVE-2026-40288.
*   Deploy the Sigma rule "Detect PraisonAI Workflow YAML Execution" to your SIEM to detect potential exploitation attempts.
*   Implement strict access controls and input validation for workflow YAML files to prevent unauthorized modification or injection of malicious code.
*   Monitor process execution logs for suspicious commands originating from PraisonAI processes, as detected by the "Suspicious Process Execution from PraisonAI" Sigma rule.
