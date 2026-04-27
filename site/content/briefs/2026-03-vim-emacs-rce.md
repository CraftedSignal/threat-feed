---
title: Vim and Emacs Remote Code Execution Vulnerabilities Triggered by File Opening
slug: 2026-03-vim-emacs-rce
description: Vulnerabilities in Vim (<=9.2.0271) and GNU Emacs allow remote code execution by opening a specially crafted file, leveraging flaws in modeline handling and Git integration, respectively.
date: "2026-03-31T21:45:14Z"
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

A researcher at Calif discovered vulnerabilities in Vim and GNU Emacs using the Claude AI assistant. The Vim vulnerability (versions 9.2.0271 and earlier) results from missing security checks in modeline handling, allowing arbitrary code execution when a specially crafted file is opened. A patch is available in version 9.2.0272. The GNU Emacs vulnerability stems from its integration with Git's version control (vc-git) and remains unpatched. Opening a file can trigger Git operations via…
