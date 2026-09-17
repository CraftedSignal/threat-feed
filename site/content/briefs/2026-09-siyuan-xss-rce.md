---
title: Remote Code Execution in SiYuan via Malicious Bookmark Labels
slug: 2026-09-siyuan-xss-rce
description: SiYuan versions prior to 3.8.4 contain a cross-site scripting vulnerability in bookmark label rendering that enables remote code execution due to insecure Electron configuration.
date: "2026-09-17T16:00:22Z"
lastmod: "2026-09-17T16:01:58Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:siyuan:siyuan:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - electron
  - xss
vendors:
  - SiYuan
products:
  - SiYuan (< 3.8.4)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can craft malicious .sy notebook files with unescaped HTML in bookmark attributes that execute scripts in the Electron renderer with access to child_process for command execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Access to child_process for command execution allows execution of arbitrary system commands.
    confidence_band: high
cves:
  - id: CVE-2026-92985
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92985
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92986
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade SiYuan to version 3.8.4 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-92985 remediation requirement
  mitigation_plan:
    - priority: immediate
      action: Upgrade to SiYuan 3.8.4
      owner: IT Operations
      addresses: CVE-2026-92985
      evidence: Source provided vulnerability window
updates:
  - at: "2026-09-17T16:01:58Z"
    level: L2
    summary: added coverage for SiYuan (< 3.8.4)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-92986
---

SiYuan versions prior to 3.8.4 contain a critical vulnerability that allows attackers to achieve remote code execution (RCE). The application fails to properly sanitize or escape bookmark labels when importing and rendering .sy notebook files within the dock tree. Because the underlying Electron framework is configured with nodeIntegration enabled, the rendering of malicious HTML payloads within these bookmark attributes allows for the execution of arbitrary JavaScript. This execution occurs within the context of the renderer process, granting the attacker access to Node.js primitives, including the child_process module, which can be leveraged to execute arbitrary system commands on the host machine. This affects all platforms where SiYuan is deployed, as it relies on the Electron-based architecture.

## Impact

Successful exploitation allows an unauthenticated attacker to execute arbitrary commands with the privileges of the user running the SiYuan application. This can lead to full system compromise, data exfiltration, or the installation of persistent backdoors. The vulnerability is highly severe because it does not require complex infrastructure, only the victim's interaction with a malicious .sy file.

## Recommendation

* Upgrade all SiYuan installations to version 3.8.4 or later immediately.
* Restrict the import of untrusted or externally sourced .sy notebook files until patches are applied.
* Review endpoint telemetry for suspicious process execution patterns originating from the SiYuan process tree.
