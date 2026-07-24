---
title: 'Open WebUI: Stored Web Worker XSS via Pyodide Leading to Server-Side RCE'
slug: 2026-07-open-webui-rce
description: A stored web worker XSS vulnerability, CVE-2026-59214, in Open WebUI versions prior to 0.10.0 allows a low-privileged user to inject malicious Python code into chat messages that, when executed by an administrator or privileged user via a 'Run' click, triggers authenticated same-origin requests to create server-side functions with arbitrary commands, leading to remote code execution on the Open WebUI server.
date: "2026-07-24T16:57:17Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openwebui:open_webui:*:*:*:*:*:*:*:*
tags:
  - xss
  - rce
  - pyodide
  - web-application
  - vulnerability
vendors:
  - Open WebUI
products:
  - Open WebUI < 0.10.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: when a victim opens it and clicks **Run** the payload executes authenticated same-origin requests
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: ""
    evidence: Pyodide's `js` bridge gives Python in the worker the same reach as inline JavaScript on the origin
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: ""
    evidence: 'creates a Function/Tool whose body runs server-side, yielding **remote code execution** ... ''content'': ''import os; os.system(''<attacker command>'')'''
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: When the victim is an admin (or a user holding `workspace.functions` / `workspace.tools` permissions) the payload creates a Function/Tool whose body runs server-side, yielding **remote code execution**.
    confidence_band: high
cves:
  - id: CVE-2026-59214
    cvss: 7.3
    epss: 0.00285
references:
  - https://github.com/advisories/GHSA-4r2p-27mh-5m22
---

A high-severity vulnerability, CVE-2026-59214, affects Open WebUI versions prior to 0.10.0, enabling stored web worker Cross-Site Scripting (XSS) via Pyodide. This flaw allows a low-privileged user to inject malicious Python code into a chat message. When a victim, specifically an administrator or a user with `workspace.functions` or `workspace.tools` permissions, views the chat and clicks "Run", the embedded Python code executes authenticated same-origin requests. This client-side execution can then be chained to create a server-side Function or Tool with arbitrary Python commands, leading to remote code execution (RCE) on the Open WebUI server. The vulnerability was published by GitHub Security Advisory (GHSA) on July 24, 2026.

## Attack Chain

1. A low-privileged attacker crafts a malicious Python payload using Pyodide's `pyodide.http.pyfetch` or the `js` module. The payload is designed to send an authenticated POST request to the `/api/v1/functions/create` endpoint.
2. The POST request body includes JSON data defining a new Function/Tool, whose `content` field contains arbitrary Python commands for server-side execution, such as `import os; os.system('<attacker command>')`.
3. The attacker stores this malicious payload within an Open WebUI chat message.
4. The attacker shares this chat message with a victim, who possesses elevated privileges (e.g., administrator or `workspace.functions`/`workspace.tools` permissions).
5. The victim accesses the shared chat message containing the malicious Python payload.
6. The victim clicks the "Run" button associated with the payload, triggering its execution within the client-side Pyodide web worker.
7. The executed Pyodide payload leverages the victim's session cookie to send the crafted authenticated `/api/v1/functions/create` request to the Open WebUI server.
8. The server processes the request, creating a new Function/Tool with the attacker's arbitrary Python code, leading to immediate remote code execution on the Open WebUI server.

## Impact

Successful exploitation of CVE-2026-59214 allows a low-privileged attacker to achieve remote code execution on the Open WebUI server. This impact is contingent on the victim being an administrator or a user holding `workspace.functions` or `workspace.tools` permissions. The attacker can then execute arbitrary system commands on the server, potentially leading to full system compromise, data exfiltration, or further lateral movement within the compromised environment. Even without RCE, the executed code can issue any authenticated request as the victim, enabling unauthorized actions or data access within the application.

## Recommendation

* Apply the patch by upgrading Open WebUI to version 0.10.0 or later to address CVE-2026-59214, ensuring Pyodide runs in a sandboxed iframe.
* If immediate upgrade is not possible, disable Pyodide code execution or configure the Code Execution / Code Interpreter engine to use a server-side option as a workaround.
* Implement robust logging and monitoring for suspicious `POST` requests targeting the `/api/v1/functions/create` endpoint on your Open WebUI instance, specifically looking for `content` parameters within the request body that contain `os.system` or other indicators of arbitrary command execution.
