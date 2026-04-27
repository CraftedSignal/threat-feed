---
title: Electron VideoFrame Context Isolation Bypass Vulnerability (CVE-2026-34780)
slug: 2026-04-electron-videoframes
description: A context isolation bypass vulnerability exists in Electron applications that bridge VideoFrame objects via contextBridge, potentially allowing an attacker with JavaScript execution in the main world to access the isolated world and Node.js APIs.
date: "2026-04-04T01:16:39Z"
severities:
  - high
tags:
  - electron
  - context-isolation
  - javascript
  - xss
  - CVE-2026-34780
  - defense-evasion
  - privilege-escalation
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
cves:
  - id: CVE-2026-34780
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34780
rules:
  - title: Detect Suspicious Process Execution via Node.js APIs (Electron VideoFrame Bypass)
    description: Detects suspicious process executions originating from Node.js APIs within Electron applications, potentially indicating a context isolation bypass exploitation attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1190
      - T1566
    data_sources:
      - process_creation
      - windows
  - title: Detect Electron App Bridging VideoFrame Objects
    description: Detects electron apps that use contextBridge to bridge VideoFrame objects, increasing their attack surface.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1190
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Electron, a framework for building cross-platform desktop applications using web technologies, is vulnerable to a context isolation bypass (CVE-2026-34780) when handling VideoFrame objects. This vulnerability affects Electron versions 39.0.0-alpha.1 to before 39.8.0, 40.0.0-alpha.1 to before 40.7.0, and 41.0.0-alpha.1 to before 41.0.0-beta.8. Specifically, applications are at risk if they utilize `contextBridge.exposeInMainWorld()` to pass a VideoFrame object from a preload script to the main…
