---
title: Cline Kanban Server Cross-Origin WebSocket Hijacking Vulnerability
slug: 2024-01-cline-kanban-websocket-hijacking
description: The `kanban` npm package, used by the `cline` CLI, has a cross-origin WebSocket hijacking vulnerability. Due to the lack of Origin header validation, any website can connect to the kanban server via WebSocket and leak sensitive data, hijack running AI agent terminals leading to remote code execution, or kill running agent tasks, resulting in information disclosure, RCE, and denial of service.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - websocket
  - cross-origin
  - rce
  - infoleak
  - dos
vendors:
  - cline
products:
  - cline
  - kanban (<= 2.13.0)
affected_os:
  - macos 15.x
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499.004
    technique_name: 'Endpoint Denial of Service: Resource Exhaustion'
references:
  - https://github.com/advisories/GHSA-5c57-rqjx-35g2
iocs:
  - type: url
    value: http://cline.sagilayani.com:1337/?key=clinevuln2026
ioc_counts:
  url: 1
rules:
  - title: Detect WebSocket Connection to Kanban API Endpoints
    description: Detects WebSocket connections to the Kanban API endpoints, which may indicate exploitation of CVE-2026-44211.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1595.002
    data_sources:
      - network_connection
      - windows
  - title: Detect Cline Kanban PoC Site Visit
    description: Detects access to the Cline Kanban exploit proof-of-concept website.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - proxy
  - title: Detect Malicious Command Injection via Terminal IO WebSocket
    description: Detects suspicious commands being sent via the Terminal IO WebSocket, potentially indicating an RCE attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - network_connection
      - windows
rules_count: 3
---

The `kanban` npm package (used by the `cline` CLI) starts a WebSocket server on `127.0.0.1:3484` with no Origin header validation, allowing any website a developer visits to silently connect to the kanban server via WebSocket. This vulnerability, present in kanban version 0.1.59 and cline up to version 2.13.0, enables attackers to leak sensitive data in real-time, including workspace filesystem paths, task titles/descriptions, and git branch info. Furthermore, attackers can hijack running AI agent terminals by injecting arbitrary prompts, leading to remote code execution, and kill running agent tasks by terminating active sessions via the control WebSocket. This vulnerability poses a significant risk to developers using the `cline` CLI, as it allows for complete compromise of their local development environment.

## Attack Chain

1.  Attacker hosts a malicious website.
2.  Victim visits the attacker-controlled website while running a vulnerable version of Cline with Kanban.
3.  The malicious website establishes a WebSocket connection to `ws://127.0.0.1:3484/api/runtime/ws` on the victim's machine.
4.  The server sends a snapshot of the developer's workspace, leaking sensitive information, including file paths, task details, and Git information.
5.  The attacker monitors the runtime WebSocket for `task_sessions_updated` messages to detect running AI agent sessions.
6.  Upon detecting a running session, the attacker connects to `ws://127.0.0.1:3484/api/terminal/io` and injects a malicious prompt followed by a carriage return.
7.  The injected prompt is executed by the AI agent, leading to remote code execution.
8.  Alternatively, the attacker could connect to `ws://127.0.0.1:3484/api/terminal/control` and send a "stop" message to terminate the task.

## Impact

The vulnerability allows for information disclosure by leaking sensitive development environment data, including workspace paths, task content, and Git branches, streamed in real-time from any website. It also enables remote code execution through terminal hijacking, where commands are injected into the AI agent when a task is active. Finally, it permits denial of service by killing any running agent task via the control WebSocket. Attack requirements: The victim must have Cline Kanban running and visit an attacker-controlled webpage.

## Recommendation

*   Deploy the following Sigma rule to detect connections to the exposed WebSocket endpoints (ws_connection_kanban_api).
*   Block access to the malicious PoC URL `http://cline.sagilayani.com:1337/?key=clinevuln2026` at the network perimeter based on the IOC list.
*   Apply the recommended fixes by the vendor, including validating the Origin header on WebSocket upgrade requests and requiring a session token.
*   Patch CVE-2026-44211 by updating `cline` to a version greater than 2.13.0.
*   Monitor network connections to `127.0.0.1:3484` to identify potential exploitation attempts using network_connection logs based on the IOC list.
