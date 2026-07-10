---
title: Marimo Pre-Auth RCE via Terminal WebSocket Authentication Bypass
slug: 2024-01-26-marimo-rce
description: Marimo versions 0.20.4 and earlier contain a pre-authentication remote code execution vulnerability in the `/terminal/ws` WebSocket endpoint, allowing unauthenticated attackers to execute arbitrary system commands, resulting in a full interactive root shell.
date: "2024-01-26T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - marimo
  - rce
  - websocket
vendors:
  - Marimo
products:
  - Marimo
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
references:
  - https://github.com/advisories/GHSA-2679-6mx9-h9xc
rules:
  - title: Detect Unauthenticated Marimo Terminal WebSocket Connection
    description: Detects unauthenticated connections to the Marimo terminal WebSocket endpoint, indicating a potential RCE exploit attempt.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - network_connection
      - linux
rules_count: 1
---

Marimo, a Python notebook tool, is vulnerable to pre-authentication remote code execution (RCE) due to a flaw in the `/terminal/ws` WebSocket endpoint. Specifically, versions up to and including 0.20.4 lack proper authentication validation on this endpoint. This allows an unauthenticated attacker to bypass security measures and establish a direct connection to a PTY (pseudo-terminal) shell. The vulnerability resides in `marimo/_server/api/endpoints/terminal.py` where the `/terminal/ws` endpoint skips authentication checks present in other WebSocket endpoints like `/ws`. Successful exploitation grants the attacker the ability to execute arbitrary system commands with elevated privileges, particularly root in default Docker deployments, posing a significant risk to affected systems.

## Attack Chain

1. An attacker sends a WebSocket connection request to the `/terminal/ws` endpoint on the target Marimo server (e.g., `ws://TARGET:2718/terminal/ws`).
2. The server, lacking authentication validation on this endpoint, directly accepts the WebSocket connection using `websocket.accept()`.
3. The server proceeds to create a PTY (pseudo-terminal) child process using `pty.fork()`.
4. This action establishes a full, interactive shell session for the attacker.
5. The attacker can then send arbitrary commands to the shell via the established WebSocket connection.
6. These commands are executed on the server with the privileges of the Marimo process (typically root in default Docker deployments).
7. The attacker receives the output of the executed commands through the WebSocket connection.
8. The attacker can continue to send and execute commands, effectively gaining complete control over the server.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to gain complete control over a Marimo server. Because the commands are executed with the privileges of the Marimo process (root within a Docker container), the attacker can perform any action on the system, including installing malware, accessing sensitive data, or disrupting services. The absence of required authentication and the ease of exploitation make this a critical vulnerability.

## Recommendation

*   Apply the suggested remediation from the Marimo advisory by adding authentication validation to the `/terminal/ws` endpoint, consistent with the `/ws` endpoint which uses `WebSocketConnectionValidator.validate_auth()`.
*   Deploy the Sigma rule "Detect Unauthenticated Marimo Terminal WebSocket Connection" to detect exploitation attempts in real-time based on network connection logs.
*   Update Marimo to a patched version (>= 0.23.0) once available to fully resolve the vulnerability.
*   As an interim mitigation, restrict network access to the Marimo server to trusted sources.
