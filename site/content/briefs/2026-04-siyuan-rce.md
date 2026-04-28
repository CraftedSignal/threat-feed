---
title: SiYuan Knowledge Management System Stored XSS Leads to RCE (CVE-2026-39846)
slug: 2026-04-siyuan-rce
description: A stored XSS vulnerability in SiYuan versions prior to 3.6.4 (CVE-2026-39846) allows remote code execution by syncing a malicious note containing a crafted table caption to another user, leading to arbitrary code execution on the victim's machine.
date: "2026-04-07T22:16:23Z"
severities:
  - critical
tags:
  - cve-2026-39846
  - rce
  - xss
  - siyuan
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-39846
    cvss: 9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39846
rules:
  - title: Detect Suspicious SiYuan Table Caption
    description: Detects potential exploitation of the SiYuan RCE vulnerability (CVE-2026-39846) by monitoring for process creations originating from the SiYuan application with suspicious command-line arguments.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.007
    data_sources:
      - process_creation
      - windows
  - title: SiYuan Network Activity
    description: Detects network connections initiated by SiYuan process that may indicate command and control activity after exploitation.
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

SiYuan, a personal knowledge management system, is vulnerable to remote code execution (RCE) due to a stored Cross-Site Scripting (XSS) vulnerability. This flaw, identified as CVE-2026-39846, affects versions prior to 3.6.4. The vulnerability stems from unsanitized table caption content within notes. An attacker can craft a malicious note containing a specifically crafted table caption with JavaScript, import this note into a shared workspace, and then wait for another user (the victim) to synchronize their workspace. When the victim opens the malicious note, the unsanitized table caption gets rendered, executing the attacker-controlled JavaScript code. Because the SiYuan Electron desktop client runs with nodeIntegration enabled and contextIsolation disabled, this Javascript can access Node.js APIs, allowing for arbitrary code execution on the victim's system.

## Attack Chain

1.  Attacker crafts a malicious note containing a table with a specially crafted caption including JavaScript. This JavaScript payload is designed to execute arbitrary commands on the victim's machine.
2.  The attacker imports this malicious note into a SiYuan workspace that is synced with other users.
3.  The victim synchronizes their SiYuan workspace, downloading the malicious note.
4.  The victim opens the note containing the malicious table.
5.  The SiYuan application renders the table, including the unsanitized table caption.
6.  The attacker's embedded JavaScript executes within the SiYuan Electron desktop client context.
7.  Due to the lack of context isolation and enabled nodeIntegration, the JavaScript can leverage Node.js APIs.
8.  The attacker achieves arbitrary code execution on the victim's machine, potentially installing malware, exfiltrating data, or compromising the system.

## Impact

Successful exploitation of CVE-2026-39846 allows a remote attacker to execute arbitrary code on a victim's machine. This could lead to complete system compromise, data theft, or installation of ransomware. Given the nature of SiYuan as a knowledge management system, successful attacks could result in the exfiltration of sensitive personal or organizational information stored within the notes. While the number of affected users and specific sectors are unknown, all users of SiYuan versions prior to 3.6.4 are vulnerable.

## Recommendation

*   Immediately upgrade SiYuan to version 3.6.4 or later to patch CVE-2026-39846.
*   Deploy the provided Sigma rule `Detect Suspicious SiYuan Table Caption` to detect potential exploitation attempts by monitoring process creations originating from the SiYuan application.
*   Monitor network connections initiated by the SiYuan application for unusual outbound traffic as a potential sign of post-exploitation activity, using the Sigma rule `SiYuan Network Activity`.
