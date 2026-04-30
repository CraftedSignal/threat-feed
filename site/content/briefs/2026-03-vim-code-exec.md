---
title: Vim Code Execution Vulnerability via Crafted Files (CVE-2026-34714)
slug: 2026-03-vim-code-exec
description: Vim versions before 9.2.0272 allow code execution upon opening a specially crafted file due to %{expr} injection in tabpanel lacking P_MLE in the default configuration, potentially leading to arbitrary code execution.
date: "2026-03-30T19:16:26Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve-2026-34714
  - code-execution
  - vim
  - injection
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34714
  - https://github.com/vim/vim/commit/664701eb7576edb7c7c7d9f2d600815ec1f43459
  - https://github.com/vim/vim/releases/tag/v9.2.0272
  - https://github.com/vim/vim/security/advisories/GHSA-2gmj-rpqf-pxvh
  - https://www.openwall.com/lists/oss-security/2026/03/30/3
rules:
  - title: Detect Suspicious Vim File Open with Expr Injection
    description: Detects attempts to exploit the Vim %{expr} injection vulnerability by monitoring for vim processes opening files with suspicious content.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - linux
  - title: Detect Execution from Suspicious Vim Process
    description: Detects potential code execution originating from a Vim process, indicative of exploitation attempts.
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

Vim, a widely used text editor, is susceptible to a critical vulnerability (CVE-2026-34714) affecting versions prior to 9.2.0272. This flaw allows for arbitrary code execution simply by opening a malicious file. The vulnerability stems from a %{expr} injection vulnerability within the tabpanel component, specifically when it lacks the P_MLE protection. The default configuration of Vim is susceptible, amplifying the risk. An attacker can craft a Vim file that, when opened, will trigger the…
