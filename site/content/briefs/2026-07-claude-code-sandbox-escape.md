---
title: Claude Code Sandbox Escape via Git Worktree Path Confusion (CVE-2026-55607)
slug: 2026-07-claude-code-sandbox-escape
description: A high-severity sandbox escape vulnerability, CVE-2026-55607, exists in Claude Code's worktree handling, allowing attackers to achieve unsandboxed code execution by manipulating symlinks and exploiting Git fsmonitor during worktree operations to overwrite user home directory files like .zshenv, requiring a user to clone a malicious repository and run Claude Code against it.
date: "2026-07-24T16:58:16Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:anthropic:claude_code:*:*:*:*:*:node.js:*:*
tags:
  - sandbox-escape
  - code-execution
  - git
  - path-confusion
  - symlink
vendors:
  - Anthropic
products:
  - Claude Code (>= 2.1.38, < 2.1.163)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: leading to code execution outside of seatbelt sandbox restrictions.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Defenses
    evidence: leading to code execution outside of seatbelt sandbox restrictions.
    confidence_band: med
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: overwrite files in the user's home directory (such as .zshenv)
    confidence_band: med
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: By exploiting symlink manipulation and git fsmonitor execution during worktree operations, an attacker could overwrite files in the user's home directory (such as .zshenv), leading to code execution outside of seatbelt sandbox restrictions.
    confidence_band: low
cves:
  - id: CVE-2026-55607
    cvss: 8.8
    epss: 0.00765
references:
  - https://github.com/advisories/GHSA-7835-87q9-rgvv
---

A high-severity sandbox escape vulnerability, identified as CVE-2026-55607, has been discovered in Claude Code, specifically impacting versions 2.1.38 through 2.1.162 of the `@anthropic-ai/claude-code` npm package. This flaw stems from Claude Code's insecure handling of Git worktrees, which permits the creation of `".git"` named worktrees and navigation outside the intended sandbox context, facilitating Git directory confusion attacks. By leveraging symlink manipulation and abusing Git's `fsmonitor` execution capabilities during worktree operations, an attacker can overwrite critical configuration files in a user's home directory, such as `.zshenv`. Successful exploitation necessitates user interaction, specifically the cloning of a malicious repository containing prompt injection content and then executing Claude Code against this repository. This can lead to arbitrary code execution outside of the application's security sandbox, posing a significant risk for data compromise and system control. The vulnerability was reported by hackerone.com/metnew and has since been patched.

## Attack Chain

1. An attacker crafts a specialized malicious Git repository containing specific worktree configurations and prompt injection content.
2. The malicious repository is designed to exploit the worktree handling vulnerability within Claude Code.
3. A victim is induced, likely through social engineering or other means, to clone this malicious repository onto their system.
4. The victim then runs the vulnerable Claude Code application (version >= 2.1.38, < 2.1.163) against the cloned malicious repository.
5. During Claude Code's internal Git worktree operations, the attacker's crafted repository leverages symlink manipulation and triggers Git's `fsmonitor` execution feature.
6. This sequence of actions exploits the "Git directory confusion" vulnerability, allowing the creation of a `".git"` named worktree outside the application's sandbox.
7. The attacker then overwrites sensitive user configuration files, such as `.zshenv` or other shell initialization files, located in the victim's home directory.
8. Upon a subsequent login or shell invocation by the victim, the maliciously modified configuration file executes arbitrary code with the user's privileges, effectively achieving unsandboxed code execution.

## Impact

Successful exploitation of CVE-2026-55607 leads to a complete sandbox escape, allowing an attacker to execute arbitrary code outside the confines of the Claude Code application's security restrictions. This can result in compromise of the user's system, including data exfiltration, installation of further malware, or disruption of system operations. The vulnerability targets user-specific configuration files in the home directory, meaning an attacker could gain persistent access or elevate privileges within the user's session. While specific victim counts are not provided, any user running affected versions of Claude Code and interacting with a malicious Git repository is at risk.

## Recommendation

* Immediately update `npm/@anthropic-ai/claude-code` to version 2.1.163 or later to patch CVE-2026-55607.
* Educate users about the risks of cloning untrusted Git repositories and running applications like Claude Code against them.
* Monitor file system events for unusual modifications to shell configuration files (e.g., `.zshenv`, `.bashrc`, `.profile`) in user home directories, particularly after Git operations or application launches.
