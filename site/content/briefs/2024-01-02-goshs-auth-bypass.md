---
title: Goshs Authentication Bypass via Share Token
slug: 2024-01-02-goshs-auth-bypass
description: Goshs is vulnerable to an authentication bypass via share tokens, allowing attackers to bypass authentication checks by using a valid share token in conjunction with other functionalities like WebSocket connections to gain unauthorized access and execute arbitrary commands on the server.
date: "2026-04-01T20:58:48Z"
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
ioc_counts:
  url: 2
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

Goshs versions 1.1.0 and later are susceptible to an authentication bypass vulnerability (CVE-2026-34581) when using share tokens. The vulnerability resides in the `BasicAuthMiddleware` which prioritizes token validation over credential checks. This allows an attacker with a valid share token to bypass all authentication and access restricted functionalities such as directory listing, file deletion, clipboard access, WebSocket connections, and CLI command execution. A patch is available in…
