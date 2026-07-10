---
title: SiYuan Stored XSS to RCE via CSS Snippet Breakout (CVE-2026-54067)
slug: 2026-07-siyuan-xss-rce
description: A critical stored cross-site scripting (XSS) vulnerability in SiYuan (CVE-2026-54067) allows an attacker with workspace write access to execute arbitrary JavaScript, which can escalate to remote code execution (RCE) on Electron desktop builds due to `nodeIntegration:true` settings, by injecting a malicious CSS snippet that bypasses security controls and executes automatically upon application boot.
date: "2026-07-10T19:28:53Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - xss
  - rce
  - siyuan
  - electron
  - vulnerability
  - remote-code-execution
  - cross-site-scripting
vendors:
  - SiYuan
products:
  - SiYuan v3.6.5
  - go/github.com/siyuan-note/siyuan/kernel < 0.0.0-20260628153353-2d5d72223df4
affected_os:
  - Windows
  - macOS
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: A payload like `</style><img src=x onerror="...">` runs arbitrary JavaScript in the renderer. On Electron desktop builds the renderer runs with `nodeIntegration:true`, so `require('child_process')` is reachable from the injected handler and the XSS chains to host RCE.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: 'Snippets sync via the workspace repository, so an attacker with write access to any synced workspace plants the payload once and it fires on every device that pulls. The payload fires whenever the renderer refreshes snippets: on boot, on manual reload, or on a `reloadSnippet` WebSocket event.'
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Defense Evasion
    evidence: The bug also bypasses the user's `enabledCSS` / `enabledJS` separation. A user who turned `enabledJS` off was making a deliberate call not to run untrusted JavaScript; the CSS path runs it anyway.
    confidence_band: high
cves:
  - id: CVE-2026-54067
    cvss: 9.9
    epss: 0.00307
references:
  - https://github.com/advisories/GHSA-mvjr-vv3c-w4qv
iocs:
  - type: url
    value: http://localhost:16806/api/snippet/setSnippet
  - type: payload
    value: </style><img src=x onerror="document.title=\"SIYUAN_XSS\";window.__siyuan_xss=true">
  - type: payload
    value: <img src=x onerror="require('child_process').execSync('open /Applications/Calculator.app')">
  - type: docker-image
    value: b3log/siyuan:latest
ioc_counts:
  docker-image: 1
  payload: 2
  url: 1
rules:
  - title: Detect SiYuan Electron RCE via Suspicious Child Process (CVE-2026-54067) - Windows
    description: Detects CVE-2026-54067 exploitation where a malicious CSS snippet in SiYuan's Electron app uses `child_process.execSync` to execute arbitrary commands, leading to RCE by monitoring for suspicious child processes spawned by SiYuan on Windows.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - impact
    techniques:
      - T1059
      - T1059.007
      - T1491
    data_sources:
      - process_creation
      - windows
  - title: Detect SiYuan Electron RCE via Suspicious Child Process (CVE-2026-54067) - macOS
    description: Detects CVE-2026-54067 exploitation where a malicious CSS snippet in SiYuan's Electron app uses `child_process.execSync` to execute arbitrary commands, leading to RCE by monitoring for suspicious child processes spawned by SiYuan on macOS.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - impact
    techniques:
      - T1059
      - T1059.007
      - T1491
    data_sources:
      - process_creation
      - macos
rules_count: 2
---

A critical stored cross-site scripting (XSS) vulnerability, tracked as CVE-2026-54067, has been identified in SiYuan, a note-taking application. This flaw affects versions up to `go/github.com/siyuan-note/siyuan/kernel < 0.0.0-20260628153353-2d5d72223df4`, including Electron desktop builds. An attacker with write access to a SiYuan workspace can exploit this by injecting a specially crafted CSS snippet containing `</style>` to break out of the HTML context. The application's `renderSnippet()` function, using `insertAdjacentHTML`, fails to properly sanitize user-controlled CSS content, leading to the execution of arbitrary JavaScript. On Electron desktop clients, which are configured with `nodeIntegration:true`, this XSS can be escalated to remote code execution (RCE) by leveraging Node.js `child_process` modules. The malicious snippet, once stored in the workspace configuration (`data/snippets/conf.json`), persists and automatically executes on every synced device upon application boot or snippet reload, without requiring user interaction, and also bypasses user-configured `enabledJS` settings.

## Attack Chain

1. An attacker gains write access to a SiYuan workspace via compromised credentials, shared filesystem access, or other means.
2. The attacker crafts a malicious CSS snippet payload, such as `</style><img src=x onerror="require('child_process').execSync('open /Applications/Calculator.app')">`.
3. The attacker uses the `/api/snippet/setSnippet` endpoint to store this payload in the SiYuan workspace configuration, specifically in `data/snippets/conf.json`.
4. A victim launches or restarts their SiYuan desktop application (Electron build) which is synced with the compromised workspace.
5. During application boot or snippet reload, the SiYuan renderer fetches the malicious snippet via `/api/snippet/getSnippet`.
6. The `renderSnippet()` function uses `document.head.insertAdjacentHTML("beforeend", ...)` to inject the snippet directly into a `<style>` tag.
7. The `</style>` in the payload breaks out of the intended HTML context, causing the injected `<img>` tag and its `onerror` JavaScript attribute to be parsed and executed by the browser engine.
8. Because the Electron app is configured with `nodeIntegration:true`, the `onerror` handler's JavaScript can access Node.js APIs like `require('child_process')`, enabling `execSync()` to execute arbitrary commands, resulting in Remote Code Execution.

## Impact

Successful exploitation of CVE-2026-54067 results in stored cross-site scripting (XSS) on SiYuan web, mobile, and Docker web builds, and escalates to remote code execution (RCE) on Electron desktop builds (Windows, macOS, Linux). The malicious payload executes automatically when the application boots or snippets are reloaded, requiring no further user interaction beyond having the application open. This bypasses the user's explicit intent to disable JavaScript execution, presenting a significant security risk. Any SiYuan user whose workspace has been compromised with write access is exposed to this vulnerability, leading to potential data theft, system compromise, or further network penetration.

## Recommendation

* Patch CVE-2026-54067 by updating SiYuan to version `0.0.0-20260628153353-2d5d72223df4` or later, which addresses the improper sanitization of CSS snippets.
* Deploy the Sigma rules "Detect SiYuan Electron RCE via Suspicious Child Process (CVE-2026-54067) - Windows" and "Detect SiYuan Electron RCE via Suspicious Child Process (CVE-2026-54067) - macOS" to your endpoint detection and response (EDR) or security information and event management (SIEM) system to detect suspicious process creations originating from the SiYuan application.
* Monitor `process_creation` logs for the SiYuan application for any unusual child processes, especially shell interpreters (`cmd.exe`, `powershell.exe`, `sh`, `bash`) or unexpected executables.
