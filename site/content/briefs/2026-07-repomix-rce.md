---
title: repomix CLI Command Injection (RCE) via --remote-branch (CVE-2026-49987)
slug: 2026-07-repomix-rce
description: The `repomix` CLI tool is vulnerable to command injection (CVE-2026-49987) via unsanitized user input in the `--remote-branch` argument, allowing attackers to inject arbitrary `git` command-line options like `--upload-pack` and achieve remote code execution with the privileges of the running user, potentially leading to CI/CD pipeline compromise.
date: "2026-07-03T12:38:08Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-injection
  - rce
  - git
  - supply-chain
  - dependency
  - linux
vendors:
  - yamadashy
products:
  - repomix (< 1.14.1)
affected_os:
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Create an executable bash script that writes system execution context to a file. ... `git` invokes the payload binary via transport helper
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: This bypasses the existing `dangerousParams` blocklist implemented in `validateGitUrl()`.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-9mm9-rqhj-j5mx
rules:
  - title: Detect CVE-2026-49987 Exploitation - Git --upload-pack Injection
    description: Detects CVE-2026-49987 exploitation - `git` process creation with a suspicious `--upload-pack` argument, indicating command injection through `repomix`.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

The `repomix` CLI tool, a utility for managing repositories, contains a critical command injection vulnerability (CVE-2026-49987) in versions prior to 1.14.1. Discovered by Abhijith S. (@kakashi-kx), this flaw stems from improper handling of the `--remote-branch` argument within the `src/core/git/gitCommand.ts` file. User-controlled input for `--remote-branch` is passed directly to `git fetch` and `git checkout` subprocesses via `child_process.execFileAsync` without proper sanitization or the use of `--` positional delimiters. This allows an attacker to inject arbitrary `git` command-line options, notably `--upload-pack`, alongside SSH or local remote URLs. The vulnerability effectively bypasses an existing `dangerousParams` blocklist designed to prevent such attacks, as this validation was not applied to the `remoteBranch` parameter. Successful exploitation grants remote code execution capabilities, enabling an attacker to compromise systems running `repomix` with the privileges of the executing user, making CI/CD environments a significant target.

## Attack Chain

1.  An attacker invokes the `repomix` CLI tool, likely through a script or automated process.
2.  The attacker supplies a specially crafted `--remote-branch` argument, for example, `--upload-pack=/tmp/malicious-pack`, to inject malicious options into the `git` command.
3.  `repomix`'s `execGitShallowClone` function in `src/core/git/gitCommand.ts` is called internally.
4.  The malicious `--remote-branch` argument, containing the injected `--upload-pack` option, is passed unsanitized to `deps.execFileAsync` which executes `git fetch`.
5.  The `git` process interprets `--upload-pack=/tmp/malicious-pack` as a valid argument to specify an alternate program for `upload-pack` operations.
6.  `git` attempts to invoke the attacker-controlled binary or script, such as `/tmp/malicious-pack`, as part of its transport helper process.
7.  The `/tmp/malicious-pack` script executes arbitrary commands (e.g., `id >> /tmp/repomix-pwned.txt`) on the compromised system.
8.  Remote Code Execution is achieved, allowing the attacker to run commands with the privileges of the user who executed `repomix`.

## Impact

The primary impact of CVE-2026-49987 is remote code execution (RCE) on the system where `repomix` is executed. This grants attackers complete system compromise capabilities with the privileges of the running user. A significant concern is the potential compromise of CI/CD environments; if `repomix` is used in automated pipelines and its `--remote-branch` parameter is populated by external or untrusted triggers (e.g., webhook payloads, pull request titles), attackers can leverage this vulnerability to gain control of build servers. This could lead to exfiltration of sensitive data, deployment of malicious code, or further lateral movement within an organization's infrastructure.

## Recommendation

*   Update `repomix` to version 1.14.1 or later immediately to patch CVE-2026-49987.
*   Deploy the provided Sigma rule to detect `git` process creation with suspicious `--upload-pack` arguments.
*   Ensure `process_creation` logging for Linux systems is enabled and configured to capture command-line arguments to activate the detection rule.
*   Review any CI/CD pipelines or automated workflows that utilize `repomix` and where the `--remote-branch` parameter might be populated by untrusted or external input.
