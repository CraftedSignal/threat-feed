---
title: 'Open WebUI: Cross-User Code-Interpreter and Tool Execution via Unvalidated Socket.IO Session ID'
slug: 2026-07-open-webui-cross-user-rce
description: An authenticated low-privilege user can exploit CVE-2026-59216 in Open WebUI versions prior to 0.10.0 to execute arbitrary Python code or tools within another user's authenticated session by supplying an unvalidated `session_id`, which, if targeting an administrator, leads to remote code execution on the server as the root process.
date: "2026-07-24T17:04:31Z"
lastmod: "2026-07-24T20:53:43Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openwebui:open_webui:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - rce
  - session-hijacking
  - open-webui
  - python
  - vulnerability
  - web-application
  - identity-spoofing
  - privilege-escalation
vendors:
  - Open WebUI
products:
  - Open WebUI (< 0.10.0)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An authenticated low-privilege user can execute arbitrary code-interpreter Python and tools inside another user's authenticated session.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: When the victim is an administrator, that hijacked context reaches the admin-only Functions API, whose source is executed server-side, yielding remote code execution as the server process (root in the default container).
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1134
    technique_name: Access Token Manipulation
    evidence: A normal authenticated user can make the terminal proxy present another user's identity to the upstream backend coordinator. On backend coordinator-backed (`policy_id`) servers that scope terminal containers by `user_id`, this reaches another user's terminal scope; combined with a known active session ID [...] it allows attaching to that user's live PTY.
    confidence_band: high
cves:
  - id: CVE-2026-59216
    cvss: 7.7
    epss: 0.00308
references:
  - https://github.com/advisories/GHSA-74h3-cxq7-vc5q
  - https://github.com/advisories/GHSA-j657-m4c4-24jq
rules:
  - title: Detects CVE-2026-59224 Exploitation - Open WebUI ws_terminal Session ID Injection
    description: Detects CVE-2026-59224 exploitation attempts by monitoring webserver logs for requests to the Open WebUI ws_terminal endpoint where the session_id parameter within the URL path contains URL-encoded query delimiters ('%3F' or '%26') followed by a 'user_id=' parameter, indicating an identity spoofing attempt.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1134
      - T1134.001
    data_sources:
      - webserver
rules_count: 1
updates:
  - at: "2026-07-24T20:53:43Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-59224 Exploitation - Open WebUI ws_terminal Session ID Injection'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-j657-m4c4-24jq
---

CVE-2026-59216 impacts Open WebUI versions prior to 0.10.0, allowing an authenticated low-privilege user to execute arbitrary code-interpreter Python commands and tools within another user's authenticated session. The vulnerability stems from the `get_event_call()` function in `backend/open_webui/socket/main.py`, which delivers `execute:python` or `execute:tool` events to a client-supplied `session_id` without validating that the session belongs to the requesting user. The malicious `session_id` is supplied in the request body for chat completions and is not validated against the authenticated user's actual session. Attackers can obtain a victim's live session ID through the `ydoc:document:join` event, which exposes collaborator socket IDs in shared notes. If the targeted victim is an administrator, the hijacked session can interact with the admin-only Functions API, leading to server-side remote code execution as the root process. This vulnerability was confirmed on `ghcr.io/open-webui/open-webui:0.9.6` and the `v0.9.6` tag, with a proof of concept demonstrating root-level RCE.

## Attack Chain

1. An attacker establishes an authenticated session as a low-privilege user in Open WebUI.
2. The attacker shares a note with a targeted victim, such as an administrator.
3. The victim opens the shared note while online, leading to the disclosure of their live `session_id` to the attacker via the `ydoc:document:join` event.
4. The attacker crafts a `POST /api/v1/chat/completions` request, including a malicious payload (e.g., Python code for arbitrary command execution) and the victim's obtained `session_id` in the request body.
5. Due to the lack of ownership validation in the `get_event_call()` function, the Open WebUI server routes the `execute:python` or `execute:tool` event to the victim's browser context, effectively hijacking their session.
6. The victim's browser executes the attacker-chosen code or tool within their authenticated session.
7. If the victim is an administrator, the hijacked session can then make calls to the `POST /api/v1/functions/create` API with attacker-controlled source code.
8. The Functions API, designed for administrator code execution, executes the attacker's supplied source server-side, resulting in remote code execution as the server process, often with root privileges in the default container.

## Impact

Successful exploitation of CVE-2026-59216 allows an authenticated attacker to achieve full session compromise against any Open WebUI user, enabling them to act with the victim's identity and origin. This means the attacker can perform any actions the victim is authorized to do within the application. If the targeted victim holds administrative privileges, the hijacked session can be leveraged to achieve server-side remote code execution as the root process, as demonstrated by the proof-of-concept returning `uid=0(root)`. This grants attackers complete control over the Open WebUI instance and potentially the underlying server, posing a critical risk to data confidentiality, integrity, and availability.

## Recommendation

* Upgrade Open WebUI installations to version 0.10.0 or later to patch CVE-2026-59216, which includes the necessary session ownership validation in `get_event_call`.
* Monitor server process creation logs on Linux systems running Open WebUI for unusual child processes spawned by the Open WebUI application, particularly if the Open WebUI process runs as root and the spawned processes include shell interpreters (`sh`, `bash`) with suspicious command line arguments.
* Implement application-level logging to detect suspicious `execute:python` or `execute:tool` events targeting sessions other than the originating user's.
* Monitor calls to the `POST /api/v1/functions/create` API for activity originating from non-administrator accounts or from sessions exhibiting other anomalous behaviors.
