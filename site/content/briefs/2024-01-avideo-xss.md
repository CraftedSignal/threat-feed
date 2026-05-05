---
title: AVideo Unauthenticated Cross-User JavaScript Execution via YPTSocket Vulnerability
slug: 2024-01-avideo-xss
description: AVideo is vulnerable to unauthenticated cross-site scripting (XSS) due to an incomplete server-side fix for a YPTSocket `autoEvalCodeOnHTML` eval sink, allowing an attacker to bypass the fix by nesting the payload under a top-level `json` field, leading to arbitrary JavaScript execution in any logged-in user's browser session.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - avideo
  - xss
  - websocket
  - vulnerability
vendors:
  - wwbn
products:
  - AVideo (<= 29.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0042
    tactic_name: Defense Evasion
    technique_id: T1505
    technique_name: Server-Side Component
references:
  - https://github.com/advisories/GHSA-ghcv-22jf-vfxm
rules:
  - title: Detect AVideo YPTSocket autoEvalCodeOnHTML Bypass
    description: Detects attempts to exploit the AVideo YPTSocket autoEvalCodeOnHTML vulnerability by monitoring for WebSocket messages containing the `autoEvalCodeOnHTML` field within a `json` field.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.007
    data_sources:
      - webserver
      - linux
  - title: Detect AVideo WebSocket connection to exploit XSS
    description: Detects a WebSocket connection attempt to AVideo that may be used to exploit the XSS vulnerability. This focuses on suspicious parameters in the WebSocket URL.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1505
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

AVideo is vulnerable to an unauthenticated cross-site scripting (XSS) vulnerability stemming from an incomplete fix for the YPTSocket `autoEvalCodeOnHTML` eval sink (GHSA-gph2-j4c9-vhhr). The initial patch only stripped the payload when present under `$json['msg']`, but the relay function `msgToResourceId()` prioritizes `$msg['json']` before `$msg['msg']`. An unauthenticated attacker can exploit this flaw by obtaining a WebSocket token from `plugin/YPTSocket/getWebSocket.json.php`, connecting to the WebSocket server, and sending a message with `autoEvalCodeOnHTML` nested under a top-level `json` field. This bypasses the strip branch, delivering the payload verbatim to any logged-in user identified by `to_users_id`, and the client script executes it via `eval()`. Versions of AVideo up to and including 29.0 are affected if they have not implemented the recommended fixes.

## Attack Chain

1.  An unauthenticated attacker requests a WebSocket token from `plugin/YPTSocket/getWebSocket.json.php`.
2.  The server issues a valid WebSocket token without authentication or CSRF checks.
3.  The attacker establishes a WebSocket connection to the server using the obtained token.
4.  The attacker crafts a malicious message containing JavaScript code within the `autoEvalCodeOnHTML` field, nested under a top-level `json` field: `{"msg": "x", "json": {"autoEvalCodeOnHTML": "<js>"}, "to_users_id": <victim>}`.
5.  The attacker sends the crafted message to the WebSocket server.
6.  The server-side validation logic in `plugin/YPTSocket/Message.php` fails to properly sanitize the `autoEvalCodeOnHTML` field due to the bypass.
7.  The server relays the message to the targeted user (`to_users_id`) via the WebSocket connection.
8.  The client-side script (`plugin/YPTSocket/script.js`) receives the message and executes the JavaScript code within `autoEvalCodeOnHTML` via `eval()`, leading to XSS.

## Impact

This vulnerability allows for unauthenticated XSS and arbitrary JavaScript execution within any logged-in user's browser session. A successful exploit enables attackers to compromise the same-origin policy, potentially leading to session data exfiltration, authenticated XHR calls on the victim's behalf, privilege escalation (if targeting an administrator), and mass exploitation by enumerating active users via the `getClientsList` request. Deployments that only patched to commit `c08694bf6` remain vulnerable.

## Recommendation

-   Apply the recommended patch by scrubbing `autoEvalCodeOnHTML` from **every** outbound carrier the relay may choose in `plugin/YPTSocket/Message.php` and `plugin/YPTSocket/MessageSQLiteV2.php` as described in the advisory.
-   Harden the relay in `msgToResourceId()` (both files) by recursively walking the chosen `$obj['msg']` and unsetting `autoEvalCodeOnHTML` when the message originated from a non-PHP, non-CLI client.
-   As defense in depth, remove or gate the client-side `eval(json.msg.autoEvalCodeOnHTML)` at `plugin/YPTSocket/script.js:573-575` behind a server-signed field rather than a plain JSON key.
-   Deploy the Sigma rule `Detect AVideo YPTSocket autoEvalCodeOnHTML Bypass` to detect attempts to exploit this vulnerability by monitoring for WebSocket messages containing the `autoEvalCodeOnHTML` field within a `json` field.
