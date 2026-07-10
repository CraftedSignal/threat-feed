---
title: Flowise Airtable Agent Code Injection Vulnerability
slug: 2024-01-flowise-code-injection
description: FlowiseAI Flowise version 3.0.13 is vulnerable to code injection within the Airtable_Agent class, allowing remote attackers to execute arbitrary code due to insufficient sandboxing of LLM-generated Python scripts, leading to potential system command execution.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - code-injection
  - rce
  - flowise
vendors:
  - FlowiseAI
products:
  - Flowise
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Code Injection
references:
  - https://github.com/advisories/GHSA-v38x-c887-992f
rules:
  - title: Detect Suspicious Python Code Execution via Flowise
    description: Detects the execution of potentially malicious Python code within the Flowise environment, indicating a potential code injection vulnerability exploitation.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.002
    data_sources:
      - process_creation
      - linux
  - title: Detect Flowise Process Spawning Shell
    description: Detects instances where the Flowise process spawns a shell process, indicating a potential command execution.
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

FlowiseAI Flowise version 3.0.13, a low-code tool for building customized large language model (LLM) applications, is vulnerable to code injection. The vulnerability resides in the `Airtable_Agent` class, where insufficient sandboxing of LLM-generated Python scripts allows for arbitrary code execution. An unauthenticated attacker can exploit this by sending crafted prompts to a chatflow utilizing the Airtable Agent node, convincing the LLM to generate malicious Python code. Authenticated attackers can also control the server or Airtable table used by the chatflow to inject malicious code. The application runs on an Express web server accessible over HTTP on port 3000/TCP, making it a readily accessible target.

## Attack Chain

1.  An attacker crafts a malicious prompt designed to exploit the LLM's code generation capabilities.
2.  The attacker submits the prompt to a Flowise chatflow configured with an Airtable Agent node.
3.  The Airtable Agent fetches data from a specified Airtable table (potentially attacker-controlled).
4.  The application constructs a system prompt including table schema and the user's question for the LLM.
5.  The LLM generates a Python script based on the system prompt and the user-provided prompt.
6.  The generated Python code is stored in the `pythonCode` variable.
7.  The application evaluates the `pythonCode` within a pyodide environment without sufficient sandboxing.
8.  Malicious Python code executes arbitrary system commands on the server, resulting in remote code execution.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary Python code on the Flowise server. This can lead to the execution of arbitrary system commands, potentially allowing the attacker to gain full control of the server, exfiltrate sensitive data, or disrupt services. While the number of victims and sectors affected remain unknown, the vulnerability poses a significant risk to organizations using FlowiseAI Flowise for AI application development.

## Recommendation

*   Apply appropriate input validation and sanitization techniques to all user-provided input to prevent prompt injection attacks targeting the LLM.
*   Implement robust sandboxing mechanisms for evaluating LLM-generated Python code to restrict access to sensitive system resources.
*   Monitor network connections for suspicious activity originating from the Flowise server, potentially indicating command execution or data exfiltration.
*   Deploy the Sigma rule "Detect Suspicious Python Code Execution via Flowise" to identify instances where potentially malicious Python code is being executed within the Flowise environment.
*   Inspect web server logs for suspicious POST requests to chatflow endpoints, especially those involving the Airtable Agent node (cs-uri-query), as these requests may contain malicious prompts designed to exploit the code injection vulnerability.
*   Block the malicious URL `hxxps://github.com/FlowiseAI/Flowise` at the network perimeter to prevent the download of vulnerable Flowise versions, mitigating the risk of exploitation.
