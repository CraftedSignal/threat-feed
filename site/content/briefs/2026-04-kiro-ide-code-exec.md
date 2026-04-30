---
title: Kiro IDE Code Execution Vulnerability via Crafted Color Theme (CVE-2026-5429)
slug: 2026-04-kiro-ide-code-exec
description: CVE-2026-5429 is a code execution vulnerability in Kiro IDE before version 0.8.140 that allows a remote, unauthenticated attacker to execute arbitrary code by exploiting a crafted color theme name when a local user opens a workspace.
date: "2026-04-02T19:21:37Z"
severities:
  - high
type: advisory
types:
  - advisory
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

CVE-2026-5429 is a critical vulnerability affecting Kiro IDE versions prior to 0.8.140. The flaw stems from unsanitized input during web page generation within the Kiro Agent webview. A remote, unauthenticated attacker can exploit this by crafting a malicious color theme name. When a user opens a workspace containing this crafted theme, it could lead to arbitrary code execution on the user's machine. Successful exploitation requires the user to trust the workspace prompt, indicating a social engineering element. The vulnerability poses a significant risk as it allows for potential system compromise if a user opens a maliciously crafted workspace. Users are advised to upgrade to version 0.8.140 to mitigate this risk.

## Attack Chain

1.  Attacker crafts a malicious Kiro IDE workspace containing a specially crafted color theme name designed to inject arbitrary code.
2.  The malicious workspace is distributed to a target user via social engineering or other means.
3.  The user opens the workspace within a vulnerable version of Kiro IDE (prior to 0.8.140).
4.  Kiro IDE attempts to load the crafted color theme name within the Kiro Agent webview.
5.  Due to the lack of proper sanitization, the malicious code embedded within the color theme name is executed in the context of the webview.
6.  The attacker achieves arbitrary code execution on the user's system due to the exploited vulnerability.
7.  The attacker leverages the initial code execution to escalate privileges or install persistent backdoors.
8.  The attacker gains complete control over the user's system, enabling data exfiltration, further lateral movement, or other malicious activities.

## Impact

Successful exploitation of CVE-2026-5429 can lead to arbitrary code execution on a developer's machine. This can lead to full system compromise, including sensitive source code theft, credentials compromise, and supply chain attacks if the compromised machine is used to build and deploy software. The vulnerability impacts any user running Kiro IDE versions before 0.8.140 who opens a malicious workspace. The scope and number of potential victims are large, as it affects all users of the vulnerable versions of the Kiro IDE.

## Recommendation

*   Immediately upgrade Kiro IDE to version 0.8.140 or later to patch CVE-2026-5429 as recommended by the vendor.
*   Implement user awareness training to educate users about the risks of opening untrusted workspaces and trusting prompts within Kiro IDE.
*   Monitor process creation events for suspicious activity originating from Kiro IDE processes after a workspace is opened, using the detection rule below.
*   Deploy the provided Sigma rules to your SIEM to detect potential exploitation attempts within your environment.
