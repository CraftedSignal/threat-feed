---
title: Vim and Emacs Remote Code Execution Vulnerabilities Triggered by File Opening
slug: 2026-03-vim-emacs-rce
description: Vulnerabilities in Vim (<=9.2.0271) and GNU Emacs allow remote code execution by opening a specially crafted file, leveraging flaws in modeline handling and Git integration, respectively.
date: "2026-03-31T21:45:14Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - rce
  - vim
  - emacs
  - git
  - modeline
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
references:
  - https://www.bleepingcomputer.com/news/security/claude-ai-finds-vim-emacs-rce-bugs-that-trigger-on-file-open/
rules:
  - title: Detect Git Execution with Unusual Core.fsmonitor Configuration
    description: Detects execution of git with core.fsmonitor pointing to unusual locations, potentially indicating an attempt to exploit the Emacs vulnerability.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - linux
  - title: Detect Hidden .git Directory Creation
    description: Detects the creation of hidden .git directories, which could be a precursor to exploiting the Emacs Git integration vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A researcher at Calif discovered vulnerabilities in Vim and GNU Emacs using the Claude AI assistant. The Vim vulnerability (versions 9.2.0271 and earlier) results from missing security checks in modeline handling, allowing arbitrary code execution when a specially crafted file is opened. A patch is available in version 9.2.0272. The GNU Emacs vulnerability stems from its integration with Git's version control (vc-git) and remains unpatched. Opening a file can trigger Git operations via `vc-refresh-state`, leading to the execution of arbitrary commands defined in a user-controlled `core.fsmonitor` program within a hidden `.git/config` file. This affects users who open files from untrusted sources.

## Attack Chain

1.  Attacker creates a malicious archive containing a text file and a hidden `.git/` directory.
2.  The `.git/` directory includes a `config` file.
3.  The `config` file contains a `core.fsmonitor` entry pointing to a malicious executable.
4.  The attacker distributes the archive (e.g., via email or shared drive).
5.  Victim extracts the archive on their system.
6.  The victim opens the seemingly benign text file within GNU Emacs.
7.  GNU Emacs' `vc-git` integration triggers `vc-refresh-state`.
8.  `vc-refresh-state` causes Git to read the attacker-controlled `.git/config` file and execute the malicious `core.fsmonitor` program, achieving arbitrary code execution.

## Impact

Successful exploitation of these vulnerabilities leads to arbitrary code execution with the privileges of the user running Vim or Emacs. For Vim, all versions 9.2.0271 and earlier are affected until patched. While the Emacs vulnerability remains unpatched, it poses a significant risk to users who routinely open files from unknown or untrusted sources, potentially leading to system compromise and data breaches. The number of potential victims is substantial given the widespread use of these editors by developers and system administrators.

## Recommendation

*   Upgrade Vim to version 9.2.0272 or later to patch the RCE vulnerability related to modeline handling (refer to the Vim flaw and fix section).
*   Exercise extreme caution when opening files from unknown sources or downloaded online when using GNU Emacs due to the unpatched Git integration vulnerability (refer to the GNU Emacs points to Git section).
*   Deploy the Sigma rule to detect execution of git with unusual core.fsmonitor configuration to your SIEM and tune for your environment.
