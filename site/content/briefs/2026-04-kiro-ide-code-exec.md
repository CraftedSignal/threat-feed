---
title: Kiro IDE Code Execution Vulnerability via Crafted Color Theme (CVE-2026-5429)
slug: 2026-04-kiro-ide-code-exec
description: CVE-2026-5429 is a code execution vulnerability in Kiro IDE before version 0.8.140 that allows a remote, unauthenticated attacker to execute arbitrary code by exploiting a crafted color theme name when a local user opens a workspace.
date: "2026-04-02T19:21:37Z"
severities:
  - high
tags:
  - cve
  - cve-2026-5429
  - code-execution
  - kiro-ide
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2026-5429
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5429
  - https://aws.amazon.com/security/security-bulletins/2026-012-aws/
  - https://kiro.dev/changelog/ide/0-8/#patch-0-8-140
rules:
  - title: Detect Suspicious Process Execution from Kiro IDE
    description: Detects potentially malicious process executions originating from Kiro IDE after opening a workspace, which could indicate exploitation of CVE-2026-5429.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Network Connection from Kiro IDE
    description: Detects potentially malicious network connections originating from Kiro IDE after opening a workspace, which could indicate exploitation of CVE-2026-5429.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-5429 is a critical vulnerability affecting Kiro IDE versions prior to 0.8.140. The flaw stems from unsanitized input during web page generation within the Kiro Agent webview. A remote, unauthenticated attacker can exploit this by crafting a malicious color theme name. When a user opens a workspace containing this crafted theme, it could lead to arbitrary code execution on the user's machine. Successful exploitation requires the user to trust the workspace prompt, indicating a social…
