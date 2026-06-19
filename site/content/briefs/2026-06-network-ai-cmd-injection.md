---
title: 'Network-AI: Improper Neutralization of Special Elements used in an OS Command (CVE-2026-54051)'
slug: 2026-06-network-ai-cmd-injection
description: The `network-ai` package, versions prior to 5.9.1, is vulnerable to a critical command injection flaw (CVE-2026-54051) where the `ShellExecutor` component fails to properly neutralize shell metacharacters when processing commands, allowing an attacker to achieve arbitrary command execution as the orchestrator process by bypassing allowlist controls.
date: "2026-06-19T13:43:05Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - command-injection
  - rce
  - node.js
  - linux
  - macos
  - software-supply-chain
vendors:
  - Jovancoding
products:
  - network-ai (< 5.9.1)
affected_os:
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-qw6v-5fcf-5666
rules:
  - title: Detects CVE-2026-54051 Exploitation — Shell Command Injection via /bin/sh -c
    description: Detects CVE-2026-54051 exploitation where `/bin/sh -c` is invoked with command-line arguments containing common shell metacharacters, indicative of command injection in `network-ai` or similar vulnerable applications.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detects CVE-2026-54051 Exploitation — Suspicious 'id' Command Execution via sh
    description: Detects the execution of the `id` command specifically when it is a direct child of a `/bin/sh` process, which can indicate command injection attempts leveraging CVE-2026-54051 in `network-ai` or similar vulnerabilities.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical command injection vulnerability, tracked as CVE-2026-54051, exists in the `network-ai` npm package, specifically affecting versions prior to 5.9.1. The flaw stems from a mismatch between the `SandboxPolicy.isCommandAllowed` function, which performs allowlist glob-matching on the entire command string, and the `ShellExecutor` which then executes this string directly via `/bin/sh -c`. This discrepancy allows an attacker to inject shell metacharacters (e.g., `;`, `|`, `$(...)`) into a command that would otherwise be approved by a broad wildcard allowlist entry (e.g., `git *`, `npm *`). This bypasses the intended security control meant to contain a compromised agent, enabling arbitrary command execution with the privileges of the orchestrator process on Linux and macOS systems. The vulnerability was publicly disclosed on June 19, 2026, via a GitHub Security Advisory (GHSA-qw6v-5fcf-5666).

## Attack Chain

1.  An attacker compromises or controls a `network-ai` agent process.
2.  The `network-ai` orchestrator's `SandboxPolicy` includes a broad wildcard allowlist entry for commands (e.g., `git *`, `npm *`, `node *`).
3.  The attacker crafts a malicious command string containing shell metacharacters, such as `git status; id > /tmp/pwned.txt`.
4.  The `SandboxPolicy.isCommandAllowed` function evaluates the full malicious string, and due to the glob-matching logic, it incorrectly determines the command is allowed.
5.  The `ShellExecutor.execute` method proceeds to execute the approved string by invoking `/bin/sh -c "git status; id > /tmp/pwned.txt"`.
6.  The `/bin/sh` interpreter processes the shell metacharacters (specifically the semicolon), executing both `git status` and the injected `id > /tmp/pwned.txt` command.
7.  Arbitrary command execution is achieved, typically as the orchestrator process, allowing the attacker to bypass the intended sandbox controls and potentially escalate privileges or exfiltrate data.

## Impact

Successful exploitation of CVE-2026-54051 leads to arbitrary command execution on the system running the `network-ai` orchestrator process. This vulnerability completely undermines the primary security mechanism designed to prevent a compromised agent from executing unauthorized commands. Attackers can leverage this to gain full control over the orchestrator, leading to data exfiltration, further lateral movement, or deployment of additional malicious payloads. While specific victim numbers are not provided, any organization utilizing `network-ai` with broad wildcard allowlist entries in its `SandboxPolicy` on Linux or macOS systems is susceptible to this critical flaw.

## Recommendation

*   **Upgrade immediately:** Update `network-ai` package to version 5.9.1 or later to apply the patch for CVE-2026-54051.
*   **Refine allowlists:** Review and harden `SandboxPolicy` allowlist configurations, avoiding overly broad wildcard entries like `node *` or `npm *` even after patching.
*   **Enable logging:** Ensure `process_creation` logging (e.g., via Sysmon for Linux/macOS) is enabled to capture execution of shell interpreters and their command-line arguments.
*   **Deploy Sigma rules:** Deploy the provided Sigma rules to detect suspicious `sh -c` invocations and anomalous command executions.
