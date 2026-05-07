---
title: AI Agent Frameworks Vulnerable to RCE via Prompt Injection
slug: 2026-05-ai-agent-rce
description: AI agents using frameworks like Microsoft's Semantic Kernel are vulnerable to remote code execution (RCE) via prompt injection by manipulating plugin parameters due to unsafe data handling.
date: "2026-05-07T20:22:39Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:microsoft:semantic_kernel:*:*:*:*:*:python:*:*
tags:
  - ai
  - prompt-injection
  - rce
  - semantic-kernel
vendors:
  - Microsoft
products:
  - Semantic Kernel
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.006
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-26030
    cvss: 9.9
    epss: 0.00103
  - id: CVE-2026-25592
    cvss: 9.9
    epss: 0.00067
references:
  - https://www.microsoft.com/en-us/security/blog/2026/05/07/prompts-become-shells-rce-vulnerabilities-ai-agent-frameworks/
rules:
  - title: Detect CVE-2026-26030 Exploitation Attempt via Malicious Prompt
    description: Detects CVE-2026-26030 exploitation — Attempts to inject code into the filter function via malicious prompts containing code execution payloads.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.006
    data_sources:
      - webserver
  - title: Detect Suspicious Process Execution from AI Agent
    description: Detects suspicious processes being spawned from an AI agent process, indicating potential RCE.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

AI agents, enhanced with plugins in frameworks like Semantic Kernel, now actively operate on networks, creating execution risks beyond content issues. This research highlights vulnerabilities (CVE-2026-26030, CVE-2026-25592) in Microsoft's Semantic Kernel, which could turn prompt injection into remote code execution (RCE). A single, crafted prompt can trigger unauthorized code execution, like launching calc.exe, on the host system without traditional exploits. The AI model correctly parses language into tool schemas; however, the framework's trust in this parsed data creates vulnerabilities. This post details the identified vulnerabilities in Semantic Kernel, mitigation steps, and ways to assess potential exposure and investigate possible exploitation.

## Attack Chain

1.  Attacker identifies an AI agent using a vulnerable framework like Semantic Kernel.
2.  The agent has a search plugin backed by an In-Memory Vector Store.
3.  The attacker injects malicious code into a prompt, exploiting a prompt injection vulnerability.
4.  The AI model parses the injected prompt and passes the malicious payload to the search plugin.
5.  The search plugin's filter function, which uses unsafe string interpolation, incorporates the malicious code into an `eval()` statement.
6.  The `eval()` statement executes the injected code, achieving arbitrary code execution on the host.
7.  The attacker gains control of the system running the AI agent.
8.  The attacker can perform malicious actions such as data exfiltration, lateral movement, or deploying ransomware.

## Impact

Successful exploitation of these vulnerabilities could lead to unauthorized code execution on systems running AI agents. This can result in data breaches, system compromise, and further malicious activities. Vulnerable Semantic Kernel frameworks are used in various applications. Exploitation could lead to complete system takeover, depending on the privileges of the account running the AI agent.

## Recommendation

*   Apply patches for CVE-2026-26030 and CVE-2026-25592 in Semantic Kernel to prevent unsafe string interpolation.
*   Deploy the Sigma rule "Detect CVE-2026-26030 Exploitation Attempt via Malicious Prompt" to identify potential exploitation attempts in web server logs.
*   Review and sanitize all inputs to AI agent plugins to prevent prompt injection attacks as described in the overview section.
*   Monitor process creation events for suspicious processes spawned from the AI agent's process, leveraging the "Detect Suspicious Process Execution from AI Agent" Sigma rule.
