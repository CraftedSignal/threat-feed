---
title: PraisonAI praisonaiagents Unsafe Dynamic Module Loading Vulnerability (CVE-2026-61437)
slug: 2026-07-praisonai-dynamic-module-loading-rce
description: A critical vulnerability, CVE-2026-61437, in PraisonAI's `praisonaiagents` pip package before version 1.6.78 allows an attacker to achieve remote code execution by exploiting an unsafe dynamic module loading mechanism when a malicious workflow file and an adjacent `tools.py` are executed, bypassing sandboxing and leading to arbitrary Python code execution with workflow runner privileges.
date: "2026-07-10T15:27:32Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - supply-chain
  - rce
  - vulnerability
vendors:
  - PraisonAI
products:
  - praisonaiagents (< 1.6.78)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker who controls a workflow file and its sibling tools.py can execute arbitrary Python code with the workflow runner's privileges when the workflow is executed via WorkflowManager or after load_yaml.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: execute arbitrary Python code with the workflow runner's privileges
    confidence_band: high
cves:
  - id: CVE-2026-61437
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61437
---

CVE-2026-61437 describes an unsafe dynamic module loading vulnerability in the PraisonAI `praisonaiagents` pip package affecting versions prior to 1.6.78. Specifically, the `AgentFlow._resolve_pydantic_class` function within `src/praisonai-agents/praisonaiagents/workflows/workflows.py` improperly handles workflow steps that use a string `output_pydantic` reference. When such a workflow is processed, the framework unrestrictedly imports a sibling `tools.py` module from the workflow's directory using `importlib.exec_module`. This process bypasses intended sandboxing measures and overrides environment variables designed to restrict tool usage (e.g., `PRAISONAI_ALLOW_*_TOOLS`). An attacker who successfully compromises or crafts a workflow file and an accompanying malicious `tools.py` file can execute arbitrary Python code with the privileges of the PraisonAI workflow runner when the workflow is initiated via `WorkflowManager` or loaded with `load_yaml`, leading to remote code execution and potential data compromise.

## Attack Chain

1. An attacker crafts a malicious PraisonAI workflow file designed to exploit the vulnerability.
2. The attacker creates a malicious `tools.py` file containing arbitrary Python code (e.g., commands for system access, data exfiltration, or reverse shells) and places it in the same directory as the malicious workflow file.
3. The malicious workflow file includes a workflow step that contains a string `output_pydantic` reference, which triggers the vulnerable dynamic module loading mechanism.
4. A legitimate user or an automated process on the victim's system loads or executes the attacker-controlled workflow file using PraisonAI's `WorkflowManager` or `load_yaml` function.
5. During the execution of the workflow, PraisonAI's `AgentFlow._resolve_pydantic_class` attempts to resolve the `output_pydantic` reference specified in the malicious workflow step.
6. Due to the vulnerability, the framework proceeds to dynamically import the attacker-controlled `tools.py` file using `importlib.exec_module`, without enforcing security sandboxes or respecting `PRAISONAI_ALLOW_*_TOOLS` environment variables.
7. The arbitrary Python code embedded within the malicious `tools.py` file is executed on the system with the same privileges as the PraisonAI workflow runner.
8. The attacker achieves remote code execution, enabling them to compromise the underlying system, access sensitive data, or establish further persistence.

## Impact

Successful exploitation of CVE-2026-61437 can lead to full compromise of the system running the PraisonAI workflow. An attacker can execute arbitrary Python code, granting them the ability to install malicious software, exfiltrate sensitive data, modify system configurations, or establish persistent access. The impact extends to any data or resources accessible by the PraisonAI application, potentially affecting intellectual property, customer data, and system integrity. The CVSS v3.1 Base Score of 7.8 indicates a high severity threat, with direct implications for confidentiality, integrity, and availability.

## Recommendation

* Upgrade the `praisonaiagents` pip package to version 1.6.78 or newer immediately to mitigate CVE-2026-61437.
* Implement strict access controls over PraisonAI workflow directories and files to prevent unauthorized modification or introduction of malicious workflows and `tools.py` files.
* Monitor systems for unusual outbound network connections or process creations from the PraisonAI application, as these could indicate successful exploitation of CVE-2026-61437.
