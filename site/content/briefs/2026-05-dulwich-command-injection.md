---
title: Dulwich Command Injection Vulnerability via Merge Driver
slug: 2026-05-dulwich-command-injection
description: Dulwich is vulnerable to command injection (CVE-2026-42563). By injecting malicious file paths through a crafted git tree, an attacker can achieve arbitrary command execution when a victim merges an untrusted branch because the `ProcessMergeDriver` substitutes the file path into the merge driver command via the `%P` placeholder and executes it with `subprocess.run(..., shell=True)`.
date: "2026-05-28T22:30:17Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - command injection
  - dulwich
  - git
  - cve-2026-42563
vendors:
  - dulwich
products:
  - dulwich (>= 0.24.0, < 1.2.5)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-9277-mp7x-85jf
  - https://github.com/dulwich/dulwich
rules:
  - title: Detect Dulwich Merge Driver Command Injection
    description: Detects CVE-2026-42563 exploitation - command injection via Dulwich merge driver with a malicious path.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Dulwich Merge Driver Execution of touch
    description: Detects execution of touch command, often used in merge driver exploit attempts.
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

Dulwich, a Python implementation of Git, is susceptible to a command injection vulnerability (CVE-2026-42563) affecting versions 0.24.0 to 1.2.5. An attacker can exploit this flaw by crafting malicious file paths within a Git tree, which are then injected into merge driver commands during a merge operation. The vulnerability resides in the `ProcessMergeDriver`, where the file path (controlled by the attacker via a malicious branch) is substituted into the merge driver command via the `%P` placeholder and executed using `subprocess.run(..., shell=True)`. This allows an attacker who can cause a victim to merge an untrusted branch to achieve arbitrary command execution. This issue is significant for environments where Dulwich is used to manage Git repositories and where merges from untrusted sources are performed, potentially leading to compromise of the system executing the merge.

## Attack Chain

1.  Attacker creates a malicious Git repository with a crafted branch.
2.  The malicious branch contains a file with a specially crafted path designed for command injection.
3.  The attacker induces a victim to merge the malicious branch into their repository.
4.  During the merge process, Dulwich's `ProcessMergeDriver` is invoked for files with merge drivers configured.
5.  The malicious file path is passed to the merge driver command via the `%P` placeholder.
6.  `subprocess.run(cmd, shell=True)` executes the crafted command, injecting shell commands from the malicious path.
7.  Arbitrary commands are executed on the victim's system with the privileges of the user running the merge operation.
8.  The attacker achieves arbitrary code execution, potentially leading to complete system compromise.

## Impact

Successful exploitation of this vulnerability allows for arbitrary command execution on the affected system. This can lead to a complete compromise of the system, including data theft, modification, or destruction. The impact is especially severe if Dulwich is used in automated systems or environments where merges from untrusted sources are common. The vulnerability affects versions 0.24.0 to 1.2.5 of the `pip/dulwich` package. The number of potential victims is dependent on the number of deployments using the vulnerable versions of Dulwich that merge code from untrusted sources.

## Recommendation

*   Upgrade to Dulwich version 1.2.5 or later to remediate CVE-2026-42563.
*   Deploy the Sigma rule "Detect Dulwich Merge Driver Command Injection" to identify exploitation attempts via malicious merge driver configurations and command execution.
*   Review custom merge driver configurations to ensure proper sanitization of file paths used in merge commands to mitigate similar command injection vulnerabilities.
*   Implement controls to validate the integrity and trustworthiness of Git repositories and branches before merging them into production environments to prevent malicious code injection.
