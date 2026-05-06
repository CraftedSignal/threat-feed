---
title: Goshs Authentication Bypass via Share Token
slug: 2024-01-02-goshs-auth-bypass
description: Goshs is vulnerable to an authentication bypass via share tokens, allowing attackers to bypass authentication checks by using a valid share token in conjunction with other functionalities like WebSocket connections to gain unauthorized access and execute arbitrary commands on the server.
date: "2026-04-01T20:58:48Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication-bypass
  - code-execution
  - goshs
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1205
    technique_name: Traffic Signaling
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
references:
  - https://github.com/advisories/GHSA-jgfx-74g2-9r6g
iocs:
  - type: url
    value: https://127.0.0.1:8000/shareable.txt?token=gMP-w0hXRs-Q-FEZku63kA
ioc_counts:
  url: 1
rules:
  - title: Goshs Authentication Bypass Attempt via WebSocket
    description: Detects attempts to bypass authentication in Goshs by using a share token in conjunction with a WebSocket request.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1205
    data_sources:
      - webserver
      - linux
  - title: Goshs Command Execution via WebSocket
    description: Detects command execution attempts in Goshs via WebSocket connections after authentication bypass.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Goshs versions 1.1.0 and later are susceptible to an authentication bypass vulnerability (CVE-2026-34581) when using share tokens. The vulnerability resides in the `BasicAuthMiddleware` which prioritizes token validation over credential checks. This allows an attacker with a valid share token to bypass all authentication and access restricted functionalities such as directory listing, file deletion, clipboard access, WebSocket connections, and CLI command execution. A patch is available in version v2.0.0-beta.2. This vulnerability affects systems using goshs where authentication is enabled alongside the share token feature, potentially leading to unauthorized access and command execution.

## Attack Chain

1. A legitimate user creates a share token for a specific file using the goshs web interface or API.
2. The attacker obtains a valid share token, either through social engineering or other means.
3. The attacker crafts a malicious request to the goshs server, including the valid share token as a query parameter (e.g., `?token=`).
4. The `BasicAuthMiddleware` in goshs checks for the `token` parameter first and, upon finding a valid token, bypasses subsequent authentication checks.
5. The attacker includes a `ws` parameter in the same request (e.g., `?ws&token=`), enabling a WebSocket connection.
6. Using the established WebSocket connection, the attacker sends commands to the server by sending a JSON payload with `{"type":"command","Content":"command_to_execute"}`.
7. The server executes the attacker-supplied command, such as `id` or `cat /etc/passwd`.
8. The attacker receives the output of the executed command via the WebSocket connection, effectively achieving remote code execution.

## Impact

Successful exploitation of this vulnerability (CVE-2026-34581) allows an attacker to bypass authentication, gain unauthorized access to the goshs server, and execute arbitrary commands. This can lead to complete system compromise, data exfiltration, and denial-of-service. Since the vulnerability exists in a widely used web file server, a successful attack could impact numerous organizations using goshs.

## Recommendation

*   Upgrade to goshs version v2.0.0-beta.2 or later to patch CVE-2026-34581, as the vulnerability is fixed in that version ([https://github.com/patrickhener/goshs/releases/tag/v2.0.0-beta.2](https://github.com/patrickhener/goshs/releases/tag/v2.0.0-beta.2)).
*   Monitor web server logs for requests containing both `token` and `ws` parameters in the query string, which may indicate an attempt to exploit this vulnerability (see the detection rule below).
*   Implement network monitoring to detect unusual WebSocket connections originating from or destined to the goshs server (see the detection rule below).
