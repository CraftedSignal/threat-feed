---
title: PraisonAI Arbitrary Code Execution Vulnerability
slug: 2026-04-praisonai-code-exec
description: PraisonAI versions 4.5.138 and below are vulnerable to arbitrary code execution due to the unsanitized import of a malicious tools.py file, leading to potential system compromise.
date: "2026-04-14T04:18:15Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - praisonai
  - code-execution
  - cve-2026-40287
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-40287
    cvss: 8.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40287
rules:
  - title: Detect tools.py Creation in PraisonAI Directory
    description: Detects the creation of a tools.py file in directories commonly used by PraisonAI, indicating potential exploitation of CVE-2026-40287.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.006
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect PraisonAI Importing tools.py
    description: Detects the PraisonAI process importing the 'tools.py' file, which is abnormal behavior that could be related to CVE-2026-40287
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.006
    data_sources:
      - image_load
      - windows
rules_count: 2
---

PraisonAI, a multi-agent teams system, is vulnerable to arbitrary code execution in versions 4.5.138 and below. The vulnerability stems from the automatic and unsanitized import of a `tools.py` file from the current working directory during application startup. Specifically, components like `call.py` (via `import_tools_from_file()`), `tool_resolver.py` (via `_load_local_tools()`), and command-line tool loading paths directly import `./tools.py` without validation, sandboxing, or user confirmation. An attacker capable of placing a malicious `tools.py` file within the directory where PraisonAI is launched can achieve immediate, arbitrary Python code execution on the host system. This can occur through shared projects, cloned repositories, or writable workspaces. Successful exploitation allows complete control over the PraisonAI process, the host system, and any associated data or credentials. Users are advised to upgrade to version 4.5.139 or later to mitigate this risk.

## Attack Chain

1.  Attacker identifies a vulnerable PraisonAI instance running version 4.5.138 or below.
2.  Attacker crafts a malicious Python script named `tools.py` containing arbitrary code.
3.  Attacker gains write access to the directory where PraisonAI is launched. This could be through a compromised shared project, a writable workspace, or other means of file upload.
4.  Attacker places the malicious `tools.py` file into the PraisonAI launch directory.
5.  PraisonAI is started or restarted, automatically importing and executing the attacker's `tools.py` file. The `call.py` or `tool_resolver.py` components trigger the import process.
6.  The malicious code in `tools.py` executes within the context of the PraisonAI process.
7.  Attacker achieves arbitrary code execution on the host system, escalating privileges as needed.
8.  Attacker uses the compromised system to steal data, install malware, or pivot to other systems.

## Impact

Successful exploitation allows attackers to execute arbitrary code on systems running vulnerable versions of PraisonAI. This can lead to complete system compromise, data theft, and potential lateral movement within the network. The vulnerability affects all users of PraisonAI versions 4.5.138 and below. The impact of this vulnerability is high due to the ease of exploitation and the potential for widespread damage.

## Recommendation

*   Upgrade PraisonAI to version 4.5.139 or later to patch CVE-2026-40287.
*   Implement strict file permission controls on the PraisonAI installation directory to prevent unauthorized file creation.
*   Deploy the Sigma rules provided below to detect suspicious file creation events in PraisonAI working directories.
*   Enable process monitoring on systems running PraisonAI to detect unexpected Python code execution.
