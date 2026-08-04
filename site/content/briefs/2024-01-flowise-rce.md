---
title: FlowiseAI Flowise CSV Agent Prompt Injection RCE Vulnerability
slug: 2024-01-flowise-rce
description: A remote code execution vulnerability exists in FlowiseAI Flowise version 3.0.13 due to insufficient sandboxing when evaluating LLM-generated Python scripts, allowing unauthenticated attackers to inject malicious code via prompts processed by the CSV Agent node, bypassing input validation, to execute arbitrary OS commands.
date: "2024-01-02T12:00:00Z"
lastmod: "2026-08-04T17:24:01Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:flowiseai:flowise:*:*:*:*:*:*:*:*
tags:
  - flowise
  - rce
  - prompt-injection
vendors:
  - Flowise
products:
  - Flowise (<= 3.1.2)
  - flowise-components (<= 3.1.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-41264
    cvss: 9.8
    epss: 0.01439
  - id: CVE-2026-69255
  - id: CVE-2026-41265
    cvss: 9.8
    epss: 0.00464
  - id: CVE-2026-46442
    cvss: 9.9
    epss: 0.03489
references:
  - https://github.com/advisories/GHSA-3hjv-c53m-58jj
  - https://github.com/advisories/GHSA-vmv7-4m6c-3cg5
rules:
  - title: Detect Suspicious Flowise CSV Agent Execution
    description: Detects process creation initiated by the Flowise server, potentially indicating code execution from the CSV Agent vulnerability.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.006
    data_sources:
      - process_creation
      - linux
  - title: Detect Outbound Connection from Flowise Server
    description: Detects suspicious outbound network connections originating from the Flowise server, indicating potential data exfiltration or command and control activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
updates:
  - at: "2026-08-04T17:24:01Z"
    level: L2
    summary: added CVE-2026-41264 +3
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-vmv7-4m6c-3cg5
---

FlowiseAI Flowise, a low-code tool for building customized large language model (LLM) applications, is vulnerable to remote code execution. Specifically, version 3.0.13 and earlier are affected. The vulnerability, identified by Trend Micro's Zero Day Initiative, stems from a lack of proper sandboxing when evaluating LLM-generated Python scripts within the `run` method of the `CSV_Agents` class. An unauthenticated attacker can exploit this vulnerability by injecting malicious code into prompts processed by the CSV Agent node, bypassing input validation to execute arbitrary OS commands on the server. Successful exploitation allows an attacker to execute code in the context of the user running the Flowise server. This impacts the confidentiality, integrity, and availability of the Flowise instance and the underlying system. The attack targets installations of Flowise on platforms like Ubuntu 25.10.

## Attack Chain

1. An attacker crafts a malicious prompt designed to exploit the CSV Agent node in Flowise.
2. The attacker sends the crafted prompt to a chatflow that utilizes the vulnerable CSV Agent node.
3. The `run` method of the `CSV_Agents` class is invoked, processing the attacker-supplied prompt.
4. The system prompt, including the user's injected payload, is sent to an LLM to generate a Python script.
5. The LLM generates a Python script containing malicious code, bypassing the `FORBIDDEN_PATTERNS` validation (e.g., importing `os` with an alias).
6. The generated Python code, including the injected malicious commands (e.g., `pandas.system("xcalc")`), is executed within a pyodide environment, lacking sufficient sandboxing.
7. The attacker-controlled command is executed on the Flowise server, in the context of the user running the server.
8. The attacker achieves arbitrary code execution, potentially leading to system compromise, data exfiltration, or denial of service.

## Impact

Successful exploitation allows an unauthenticated attacker to execute arbitrary code on the Flowise server. This can lead to a full system compromise, allowing the attacker to steal sensitive data, install malware, or disrupt services. Given Flowise's role in LLM application development, a successful attack could compromise sensitive data used by these models, or introduce malicious functionality into the models themselves. The number of affected installations is unknown, but any Flowise instance running version 3.0.13 or earlier with the CSV Agent node exposed is potentially vulnerable.

## Recommendation

*   Upgrade Flowise to a patched version greater than 3.0.13 to remediate CVE-2026-41264.
*   Deploy the Sigma rule "Detect Suspicious Flowise CSV Agent Execution" to detect attempts to exploit this vulnerability via process creation from unexpected locations.
*   Review and harden the `FORBIDDEN_PATTERNS` list in the `validatePythonCodeForDataFrame()` function to prevent bypasses, referencing the details in the overview.
*   Monitor network connections originating from the Flowise server for suspicious outbound traffic using the "Detect Outbound Connection from Flowise Server" Sigma rule.
