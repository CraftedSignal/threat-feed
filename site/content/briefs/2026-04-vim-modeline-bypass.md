---
title: Vim Modeline Sandbox Bypass Vulnerability (CVE-2026-34982)
slug: 2026-04-vim-modeline-bypass
description: A critical vulnerability in Vim versions prior to 9.2.0276 allows arbitrary OS command execution via a crafted file that bypasses the modeline sandbox due to missing security checks, potentially leading to code execution.
date: "2026-04-06T16:16:38Z"
severities:
  - critical
tags:
  - vim
  - modeline
  - sandbox-bypass
  - code-execution
  - cve-2026-34982
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-34982
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34982
  - http://www.openwall.com/lists/oss-security/2026/04/01/1
  - https://github.com/vim/vim/commit/75661a66a1db1e1f3f1245c615
  - https://github.com/vim/vim/releases/tag/v9.2.0276
  - https://github.com/vim/vim/security/advisories/GHSA-8h6p-m6gr-mpw9
ioc_counts:
  email: 1
  url: 4
rules:
  - title: Detect Suspicious Vim Process Execution
    description: Detects the execution of Vim with suspicious arguments indicative of potential exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious Vim Modelines
    description: Detects files being opened by Vim with suspicious modelines containing shell commands.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - process_creation
      - linux
  - title: Detect shell commands spawning from Vim process
    description: Detects shell commands spawning from Vim process
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

Vim, a widely used open-source command-line text editor, is susceptible to a critical vulnerability (CVE-2026-34982) affecting versions prior to 9.2.0276. This flaw allows a malicious actor to execute arbitrary operating system commands by crafting a specific file that exploits a bypass in the modeline sandbox. The vulnerability arises from the `complete`, `guitabtooltip`, and `printheader` options lacking the `P_MLE` flag, and the `mapset()` function not having a `check_secure()` call, which…
