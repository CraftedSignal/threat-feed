---
title: PraisonAI Arbitrary Code Execution via Malicious tools.py Import
slug: 2024-01-praisonai-rce
description: PraisonAI versions 4.5.138 and earlier are vulnerable to arbitrary code execution due to the automatic import and execution of a `tools.py` file from the current working directory, allowing attackers to execute arbitrary Python code.
date: "2024-01-23T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - praisonai
  - rce
  - python
vendors:
  - PraisonAI
products:
  - PraisonAI
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-g985-wjh9-qxxc
iocs:
  - type: file
    value: tools.py
ioc_counts:
  file: 1
rules:
  - title: Detect Suspicious tools.py Creation
    description: Detects the creation of a `tools.py` file with potentially malicious content based on common code execution patterns.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.006
    data_sources:
      - file_event
      - linux
  - title: PraisonAI tools.py Execution via Python
    description: Detects execution of `tools.py` by a python process, which is suggestive of the PraisonAI vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.006
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

PraisonAI, an AI agent platform, is vulnerable to arbitrary code execution. Specifically, versions 4.5.138 and earlier automatically import and execute a `tools.py` file located in the current working directory. This behavior affects components like `call.py`, `tool_resolver.py`, and various CLI tool-loading paths. An attacker can exploit this vulnerability by placing a malicious `tools.py` file in the directory where PraisonAI is launched. When PraisonAI initializes or a CLI command is executed that loads local tools, the malicious script is immediately executed, granting the attacker arbitrary Python code execution within the PraisonAI process context. This can lead to host compromise and potential data breaches.

## Attack Chain

1. The attacker identifies a PraisonAI instance and determines its working directory.
2. The attacker crafts a malicious `tools.py` file containing arbitrary Python code to execute.
3. The attacker places the malicious `tools.py` file into the PraisonAI working directory. This could be achieved via compromised credentials, file upload functionality, or other means of initial access.
4. The victim user or system executes a PraisonAI component, such as `call.py`, through a CLI command (e.g., `praisonai workflow run safe.yaml`).
5. During initialization, the PraisonAI component attempts to load local tools by importing `tools.py` from the current working directory via `import_tools_from_file()` or `_load_local_tools()`.
6. The Python interpreter executes the attacker's malicious code within `tools.py`.
7. The attacker gains control of the PraisonAI process.
8. The attacker leverages their control to compromise the host system, steal sensitive data, or pivot to other systems on the network.

## Impact

Successful exploitation allows an attacker to execute arbitrary code within the PraisonAI process. This can lead to full system compromise, including the potential to read sensitive data, install backdoors, or pivot to other systems on the network. The number of victims depends on the prevalence of vulnerable PraisonAI installations. Affected sectors are any using the PraisonAI framework. A successful attack gives the attacker full control over the host system and any data accessible to the PraisonAI process.

## Recommendation

*   Upgrade PraisonAI to a version greater than 4.5.138 to prevent the automatic import of `tools.py`.
*   Deploy the Sigma rules provided to detect the creation of `tools.py` with suspicious content (see rules below).
*   Monitor process creation events for PraisonAI processes executing Python scripts from unexpected locations, especially the current working directory, using process creation logs.
*   Implement file integrity monitoring on the PraisonAI installation directory to detect unauthorized file modifications, including the creation of `tools.py`.
