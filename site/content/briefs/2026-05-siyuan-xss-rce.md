---
title: SiYuan Stored XSS via Attribute View Name Leads to Electron Renderer RCE (CVE-2026-44670)
slug: 2026-05-siyuan-xss-rce
description: A stored cross-site scripting (XSS) vulnerability exists in SiYuan due to the kernel storing Attribute View (AV) names without HTML escaping, allowing a malicious actor to inject arbitrary HTML which leads to Node.js code execution due to insecure Electron configuration, resulting in remote code execution (RCE).
date: "2026-05-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - xss
  - rce
  - siyuan
  - cve-2026-44670
vendors:
  - GitHub
products:
  - siyuan-note/siyuan/kernel
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-2h64-c999-c9r6
rules:
  - title: Detect SiYuan XSS via Attribute View Name (CVE-2026-44670)
    description: Detects CVE-2026-44670 exploitation — monitors for the `setAttrViewName` action with suspicious HTML payloads in the SiYuan API.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.004
      - T1566.001
    data_sources:
      - webserver
  - title: Detect SiYuan Child Process Execution via Node Integration
    description: Detects exploitation of SiYuan XSS leading to child process execution via Node integration.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1566.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

SiYuan is vulnerable to a stored cross-site scripting (XSS) vulnerability (CVE-2026-44670) due to improper handling of Attribute View (AV) names. The application's kernel stores AV names without HTML escaping, and a rendering template uses raw string replacement to embed the name in HTML before pushing it to clients via WebSocket. Multiple client paths consume this value without escaping, leading to HTML injection. The main BrowserWindow runs with `nodeIntegration:true`, `contextIsolation:false`, and `webSecurity:false`, exacerbating the issue and allowing for Node.js code execution from injected HTML. This vulnerability affects SiYuan versions up to and including 3.6.5 and can be exploited through various vectors, including browser extensions, shared `.sy.zip` files, and sync replication from compromised devices, as well as Bazaar templates.

## Attack Chain

1. An attacker crafts a malicious Attribute View (AV) name containing a JavaScript payload, such as `<img src=x onerror="require('child_process').exec(process.platform==='win32'?'calc.exe':process.platform==='darwin'?'open -a Calculator':'xcalc')">`.
2. The attacker uses the SiYuan UI or API endpoint `/api/transactions` with the `setAttrViewName` action to set the crafted AV name.
3. The kernel stores the malicious AV name without proper HTML escaping in the `data/storage/av/<id>.json` file.
4. When a user opens a document bound to the malicious AV, the AV name is retrieved from storage and rendered into the user interface via WebSocket updates or direct rendering during document load.
5. The vulnerable code paths at `app/src/protyle/render/av/render.ts:120`, `app/src/protyle/header/Title.ts:396-403`, or `app/src/protyle/wysiwyg/transaction.ts:549-562,659` inject the unescaped AV name into the DOM.
6. The browser executes the injected JavaScript payload due to the lack of context isolation and disabled web security.
7. The payload executes arbitrary commands on the victim's machine. For example, it launches the calculator application using `require('child_process').exec()`.
8. The attacker achieves remote code execution (RCE) on the victim's machine with the user's privileges.

## Impact

Successful exploitation of this vulnerability leads to remote code execution (RCE) on the victim's desktop. The payload is persistent, surviving restarts and syncing across devices. The vulnerability affects all user roles (Administrator, Editor, Reader, and publish-service Visitor). After gaining RCE, an attacker can perform various malicious activities, including full filesystem read, persistence, and cloud-account pivot. The vulnerability can be exploited through browser extensions, shared `.sy.zip` files, Bazaar templates, sync peers, and co-authors on a shared workspace.

## Recommendation

*   Apply the suggested fixes from the advisory to mitigate the vulnerability in the SiYuan kernel. Specifically, use `template.HTMLEscapeString(nodeAvName)` for the `${avName}` substitution in `kernel/model/attribute_view.go`.
*   Escape the `av-names` value with `Lute.EscapeHTMLStr` in `transaction.ts:559` to prevent HTML injection via WebSocket updates.
*   Use `Lute.EscapeHTMLStr(data.name)` for both `data-title=` and the text content in `render.ts:120` to prevent HTML injection during AV rendering.
*   Escape `item.name` via `Lute.EscapeHTMLStr` and `item.id` via `escapeAttr` in `Title.ts:396` during document title rendering.
*   Deploy the Sigma rule "Detect SiYuan XSS via Attribute View Name" to detect exploitation attempts by monitoring for the `setAttrViewName` action with suspicious HTML payloads.
*   As a defense-in-depth measure, switch the main BrowserWindow to `contextIsolation: true` with a preload bridge to limit the impact of potential future renderer XSS vulnerabilities.
