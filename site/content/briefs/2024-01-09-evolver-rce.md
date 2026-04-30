---
title: Evolver Remote Code Execution via Command Injection in `_extractLLM()`
slug: 2024-01-09-evolver-rce
description: A command injection vulnerability in the `_extractLLM()` function of the evolver application allows remote attackers to execute arbitrary shell commands by injecting shell metacharacters into the `corpus` parameter, leading to potential system compromise.
date: "2024-01-09T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - command-injection
  - rce
  - evolver
vendors:
  - Evomap
products:
  - '@evomap/evolver'
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-j5w5-568x-rq53
rules:
  - title: Detect Evolver Command Injection Attempt
    description: Detects attempts to exploit the Evolver command injection vulnerability by identifying shell metacharacters within the command line of executed processes.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious Curl Usage with User-Controlled Data
    description: Detects suspicious curl commands where the data being posted appears to contain shell injection characters.  This may indicate an attempt to exploit the Evolver RCE.
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

A command injection vulnerability exists in the `_extractLLM()` function within the `src/gep/signals.js` file of the evolver application, specifically in versions prior to 1.69.3. The vulnerability stems from the function's construction of a `curl` command via string concatenation, incorporating the `corpus` parameter without sufficient sanitization. This parameter, derived from user input through the `extractSignals()` function, is susceptible to shell command substitution using the `$(...)` syntax when processed by `execSync()`. Successful exploitation grants attackers the ability to execute arbitrary shell commands within the context of the Node.js process. This flaw poses a significant risk, potentially leading to full system compromise, data exfiltration, or the installation of malicious software.

## Attack Chain

1. An attacker crafts a malicious input string containing shell metacharacters (e.g., `$(...)`).
2. This malicious string is passed as the `userSnippet` parameter to the `extractSignals()` function within `src/gep/evolver.js`.
3. The `extractSignals()` function processes the user snippet and extracts a summary.
4. The extracted summary, which includes the malicious payload, is passed as the `corpus` parameter to the vulnerable `_extractLLM()` function in `src/gep/signals.js`.
5. The `_extractLLM()` function constructs a `curl` command by concatenating strings, embedding the unsanitized `corpus` parameter within the command string.
6. The `curl` command is executed using `execSync()`, which interprets the shell metacharacters and executes the injected commands.
7. The injected commands are executed with the privileges of the Node.js process.
8. The attacker achieves remote code execution, enabling them to perform actions such as data exfiltration or system compromise.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary commands on the server hosting the evolver application. This can lead to full system compromise, allowing attackers to steal sensitive data, install malware, or pivot to other systems on the network. The vulnerability affects anyone running the evolver with the GEP (Genetic Evolution Protocol) enabled and processing user-provided content. The affected package is npm/@evomap/evolver (vulnerable: < 1.69.3).

## Recommendation

*   Upgrade the `@evomap/evolver` package to version 1.69.3 or later to patch the vulnerability.
*   Deploy the Sigma rule "Detect Evolver Command Injection Attempt" to identify attempts to exploit this vulnerability by detecting shell metacharacters in process execution logs.
*   Review and sanitize all user-provided content before it is processed by the `extractSignals()` and `_extractLLM()` functions.
*   Implement strict input validation to prevent shell metacharacters from reaching the vulnerable code.
