---
title: SiYuan Knowledge Management System RCE via Mermaid Diagram Injection
slug: 2024-01-siyuan-rce
description: 'SiYuan versions 3.6.3 and below are vulnerable to arbitrary code execution due to insecure rendering of Mermaid diagrams, allowing injected javascript: URLs within Mermaid code blocks to execute arbitrary code when a victim opens a note containing a malicious Mermaid block and clicks the rendered diagram node.'
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - siyuan
  - mermaid
  - rce
  - xss
  - electron
vendors:
  - SiYuan
products:
  - SiYuan Knowledge Management System
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-40322
    cvss: 9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40322
rules:
  - title: Detect Suspicious SiYuan Mermaid Diagram Execution
    description: Detects potential exploitation attempts of the SiYuan Mermaid diagram RCE vulnerability by monitoring for process execution originating from SiYuan with arguments indicative of command execution.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.007
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious SiYuan Network Connection After Mermaid Render
    description: Detects potential data exfiltration or command and control activity originating from SiYuan shortly after a Mermaid diagram has been rendered, indicating possible exploitation.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

SiYuan, an open-source personal knowledge management system, is susceptible to arbitrary code execution in versions 3.6.3 and below. The vulnerability stems from the insecure rendering of Mermaid diagrams, a feature used for creating visual representations. Specifically, the application renders Mermaid diagrams with `securityLevel` set to "loose", injecting the resulting SVG directly into the DOM using `innerHTML`. This insecure approach allows attacker-controlled `javascript:` URLs within Mermaid code blocks to persist in the rendered output. On desktop builds leveraging Electron, the application creates windows with `nodeIntegration` enabled and `contextIsolation` disabled. Consequently, when a user opens a note containing a malicious Mermaid block and interacts with the rendered diagram, the stored cross-site scripting (XSS) vulnerability escalates to arbitrary code execution. Users are advised to upgrade to version 3.6.4, which addresses this security flaw.

## Attack Chain

1.  Attacker crafts a malicious SiYuan note containing a Mermaid diagram.
2.  The Mermaid diagram includes a code block with a `javascript:` URL. Example: ```mermaid graph LR; A[Click me] --> B((Malicious Node)); click A "javascript:require('child_process').exec('calc.exe');" ```
3.  The attacker saves the malicious note within SiYuan.
4.  The victim opens the malicious note in the SiYuan desktop application (version 3.6.3 or earlier).
5.  SiYuan renders the Mermaid diagram with `securityLevel` set to "loose", injecting the SVG into the DOM via `innerHTML`.
6.  The malicious `javascript:` URL is embedded within the rendered SVG.
7.  The victim clicks on the rendered diagram node.
8.  Due to `nodeIntegration` being enabled and `contextIsolation` being disabled in the Electron environment, the `javascript:` URL executes arbitrary code, effectively achieving remote code execution on the victim's machine.

## Impact

Successful exploitation of this vulnerability allows attackers to execute arbitrary code on a victim's machine. This can lead to complete system compromise, including data theft, malware installation, and unauthorized access to sensitive information stored within the SiYuan knowledge base or elsewhere on the system. Given that SiYuan is often used to store personal and professional notes, the impact could be substantial for affected users. The vulnerability affects any user running SiYuan version 3.6.3 or earlier on a desktop system.

## Recommendation

*   Upgrade SiYuan to version 3.6.4 or later to patch the vulnerability (CVE-2026-40322).
*   Deploy the Sigma rule "Detect Suspicious SiYuan Mermaid Diagram Execution" to identify potential exploitation attempts.
*   Monitor process creation events for unexpected child processes spawned from SiYuan, especially those related to command execution (e.g., `cmd.exe`, `powershell.exe`).
*   If upgrading is not immediately possible, consider disabling the Mermaid diagram rendering feature within SiYuan as a temporary workaround.
