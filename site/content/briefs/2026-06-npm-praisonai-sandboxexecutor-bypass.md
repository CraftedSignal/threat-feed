---
title: npm PraisonAI SandboxExecutor allowedCommands bypass via shell chaining
slug: 2026-06-npm-praisonai-sandboxexecutor-bypass
description: A critical command injection vulnerability exists in the `npm:praisonai` package versions >= 1.2.3 and <= 1.7.1, where the `SandboxExecutor`'s `allowedCommands` policy is bypassed by allowing arbitrary shell command chaining after an allowlisted command, leading to remote code execution with the PraisonAI process privileges.
date: "2026-06-18T15:04:55Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-injection
  - npm
  - nodejs
  - sandbox-bypass
  - vulnerability
  - rce
  - server-side
vendors:
  - PraisonAI
products:
  - npm:praisonai (>= 1.2.3, <= 1.7.1)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: ""
references:
  - https://github.com/advisories/GHSA-vjv9-7m7j-h833
rules:
  - title: Detect Suspicious `sh -c` Spawns by Node.js with Shell Chaining
    description: Detects exploitation of the `npm:praisonai` vulnerability by identifying `sh -c` processes spawned by Node.js, where the command line contains shell metacharacters, indicating an attempt to bypass the `allowedCommands` policy.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

The `npm:praisonai` package, which provides "safe command execution with restrictions" via its `SandboxExecutor` and `CommandValidator` components, contains a critical vulnerability affecting versions 1.2.3 through 1.7.1. The `CommandValidator` component incorrectly processes command strings when `allowedCommands` is configured: it only checks the first whitespace-delimited token for allowlisting, while the `SandboxExecutor` subsequently passes the entire, unmodified command string to `spawn("sh", ["-c", command])`. This discrepancy allows attackers to append arbitrary shell commands using metacharacters (e.g., `;`, `&&`, `||`) after an allowlisted initial command, bypassing the intended security controls. This allows for arbitrary code execution with the privileges of the PraisonAI process if lower-trust input (such as user prompts or model output) is processed by the vulnerable component. The vulnerability is present in `src/praisonai-ts/src/cli/features/sandbox-executor.ts` and confirmed in distributed `npm:praisonai@1.7.1` files.

## Attack Chain

1.  An attacker crafts a malicious command string that begins with an allowlisted command (e.g., `echo`) followed by shell metacharacters and arbitrary commands (e.g., `echo allowed; cat /tmp/marker`).
2.  This malicious command string is supplied as input to an application, CLI tool, or agent pipeline that utilizes the `npm:praisonai` library's `SandboxExecutor` or `sandboxExec` function.
3.  The `CommandValidator` component within `praisonai` receives the command string and checks its `allowedCommands` policy by extracting only the first whitespace-delimited token (e.g., `echo`).
4.  If the first token matches an entry in the `allowedCommands` list, the `CommandValidator` incorrectly deems the entire command string valid and permits its execution.
5.  The `SandboxExecutor` proceeds to invoke `spawn('sh', ['-c', malicious_command_string])`, passing the full, unvalidated string directly to the system shell.
6.  The `sh` process interprets the shell metacharacter (e.g., `;`) as a command separator, executing both the initially allowlisted command and the subsequent arbitrary malicious commands (e.g., `cat /tmp/marker`).
7.  The attacker achieves arbitrary command execution with the privileges of the PraisonAI process, enabling actions such as reading or modifying files, invoking local tools, or causing denial of service.

## Impact

The successful exploitation of this vulnerability allows for arbitrary shell command execution within the context of the PraisonAI process. Depending on the privileges of the hosting application and the affected system, this can lead to severe consequences, including unauthorized access to sensitive data (confidentiality), modification or deletion of critical files (integrity), and disruption of service (availability). If the PraisonAI application handles lower-trust input, such as from user prompts or AI model outputs, the risk of compromise is significantly elevated. While the advisory notes a local-only proof-of-concept, the nature of the vulnerability means that any application exposing `SandboxExecutor`'s functionality to external input could be at risk.

## Recommendation

*   Upgrade `npm:praisonai` to a patched version once available. Monitor the official GitHub advisory GHSA-vjv9-7m7j-h833 for release information.
*   Deploy the provided Sigma rule "Detect Suspicious `sh -c` Spawns by Node.js with Shell Chaining" to your SIEM system to identify attempts at exploiting this vulnerability.
*   Enable comprehensive `process_creation` logging on all Linux systems running Node.js applications that might utilize `npm:praisonai` or similar command execution libraries.
*   Review applications using `npm:praisonai` versions >= 1.2.3, <= 1.7.1 to ensure that any input passed to `SandboxExecutor` or `sandboxExec` is strictly validated and sanitized, avoiding shell metacharacters.
*   As a temporary mitigation, if direct patching is not immediately feasible, consider implementing input sanitization at the application layer to strip or escape shell metacharacters before passing commands to `npm:praisonai` functions.
