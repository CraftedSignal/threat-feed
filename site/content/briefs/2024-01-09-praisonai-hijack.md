---
title: PraisonAI Browser Server Unauthenticated Session Hijacking Vulnerability
slug: 2024-01-09-praisonai-hijack
description: PraisonAI Browser Server is vulnerable to unauthenticated WebSocket client hijacking due to exposing the browser bridge on 0.0.0.0 by default and accepting WebSocket clients that omit the Origin header, allowing unauthorized remote use of a connected browser automation session.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - praisonai
  - websocket
  - session-hijacking
  - vulnerability
vendors:
  - PraisonAI
products:
  - PraisonAI Browser Server
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-8x8f-54wf-vv92
rules:
  - title: PraisonAI Browser Server Unauthenticated WebSocket Connection
    description: Detects connections to the PraisonAI Browser Server that lack an Origin header in the WebSocket handshake, indicating a potential attempt to exploit the unauthenticated session hijacking vulnerability.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
  - title: PraisonAI Start Session Command from Unauthorized Client
    description: Detects 'start_session' commands sent to the PraisonAI Browser Server from clients without a valid Origin header.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

PraisonAI Browser Server versions 4.5.138 and below expose a critical vulnerability that allows unauthenticated WebSocket clients to hijack connected extension sessions. The `praisonai browser start` command, by default, binds the browser bridge to `0.0.0.0`, making it accessible to any network client. Critically, the `/ws` endpoint accepts WebSocket connections even when the `Origin` header is omitted. This allows a malicious actor to connect to the bridge and send a `start_session` command. The server then forwards a `start_automation` message to another connected browser extension WebSocket, effectively hijacking the session. The attacker receives the resulting action/status stream, enabling unauthorized remote control of the browser automation session. This vulnerability was verified on praisonai version 4.5.134 at commit 365f75040f4e279736160f4b6bdb2bdb7a3968d4.

## Attack Chain

1. The attacker connects to the PraisonAI Browser Server's `/ws` endpoint without providing an `Origin` header in the WebSocket handshake. The server incorrectly accepts the connection due to insufficient origin validation.
2. The attacker sends a `start_session` message to the server via the WebSocket connection, specifying parameters for a new automation session (e.g., goal, model, max_steps).
3. The server searches for an idle WebSocket connection associated with a browser extension that is not currently in a session.
4. The server forwards a `start_automation` message, containing the session ID and automation parameters, to the identified browser extension.
5. The browser extension processes the `start_automation` message and begins executing the requested automation tasks.
6. The browser extension sends an `observation` message back to the server, containing details about the current state of the browser (e.g., URL, elements).
7. The server broadcasts an `action` message, containing the action to be performed by the browser extension, to all connected WebSockets associated with the same session ID, including the attacker's WebSocket.
8. The attacker receives the `action` message, effectively gaining control over the browser automation session and access to sensitive data.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to remotely control browser automation sessions managed by PraisonAI. This can lead to unauthorized browser actions, misuse of model-backed automation, and leakage of sensitive page context or automation results. The vulnerability impacts operators running `praisonai browser start` with the default host binding, users with active connected browser extension sessions, and environments where the bridge is reachable from other hosts on the network. This vulnerability affects PraisonAI versions up to and including 4.5.138.

## Recommendation

*   Apply the suggested remediations from the advisory including requiring explicit authentication for WebSocket clients, rejecting connections that omit the `Origin` header, binding the bridge to `127.0.0.1` by default, and pairing controller and extension clients explicitly.
*   Deploy the Sigma rule "PraisonAI Browser Server Unauthenticated WebSocket Connection" to detect connections to the PraisonAI Browser Server that lack an Origin header in the WebSocket handshake. This rule will help identify potential exploitation attempts (see rule below).
*   Upgrade to a patched version of PraisonAI that addresses this vulnerability. Verify that the updated version includes proper authentication and origin validation mechanisms to prevent unauthorized access.
*   Monitor network traffic to the PraisonAI Browser Server for suspicious activity, such as connections from unexpected sources or attempts to initiate automation sessions without proper authentication.
