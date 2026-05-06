---
title: DevSpace UI Server WebSocket Origin Validation Vulnerability
slug: 2024-01-devspace-websocket-vuln
description: DevSpace's UI server WebSocket accepts connections from any origin, enabling attackers to access pod logs, interactive shells, and execute commands via cross-origin WebSocket connections; versions up to 6.3.20 are affected, patched in 6.3.21.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - websocket
  - kubernetes
  - vulnerability
vendors:
  - Loft
products:
  - DevSpace UI <= 6.3.20
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Bash'
references:
  - https://github.com/advisories/GHSA-hqwm-7x7x-8379
  - https://pkg.go.dev/github.com/gorilla/websocket#hdr-Origin_Considerations
rules:
  - title: Detect DevSpace Websocket API Access From Non-Localhost
    description: Detects access to DevSpace UI API endpoints from non-localhost IP addresses, indicating potential unauthorized access.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1203
    data_sources:
      - network_connection
      - windows
  - title: Detect DevSpace Websocket API Endpoint Access
    description: Detects access to sensitive DevSpace UI API endpoints (/api/logs, /api/enter, /api/command) indicating potential exploitation.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1071.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

DevSpace, a tool for developing and deploying applications in Kubernetes, contains a vulnerability in its UI server WebSocket implementation. Versions 6.3.20 and earlier do not properly validate the origin of WebSocket connections. This allows a malicious website, visited by a developer running the DevSpace UI, to establish a cross-origin WebSocket connection to `ws://127.0.0.1:8090`. Successful exploitation grants the attacker unauthorized access to sensitive functionalities, including real-time pod log streaming, opening interactive shells within running pods, and executing pre-defined pipeline commands. This poses a significant risk to developers using DevSpace as it allows unauthorized access to and control over their Kubernetes deployments. The vulnerability is identified as CVE-2026-42283.

## Attack Chain

1. A developer runs the DevSpace UI, typically accessible at `ws://127.0.0.1:8090`.
2. The same developer uses a web browser to access the internet.
3. The developer visits a malicious website that contains JavaScript designed to exploit the DevSpace WebSocket vulnerability.
4. The malicious website's JavaScript establishes a WebSocket connection to the developer's local DevSpace UI server (`ws://127.0.0.1:8090`).
5. Because the DevSpace UI server lacks origin validation, it accepts the connection from the malicious website.
6. The attacker leverages the open WebSocket connection to access the `/api/logs` endpoint, streaming real-time pod logs.
7. The attacker utilizes the connection to execute commands via the `/api/command` endpoint.
8. The attacker gains a shell in the pod via the `/api/enter` endpoint, achieving code execution within the container.

## Impact

Successful exploitation of this vulnerability allows an attacker to gain unauthorized access to a developer's Kubernetes environment. This could lead to the exfiltration of sensitive information from pod logs, unauthorized execution of commands within pods, and potentially full compromise of the affected Kubernetes deployment. The impact is especially significant for developers working with sensitive data or critical infrastructure.

## Recommendation

*   Upgrade DevSpace to version 6.3.21 or later to patch the vulnerability (CVE-2026-42283).
*   Implement network segmentation to limit access to the DevSpace UI server to trusted networks only.
*   Monitor network connections for unusual WebSocket connections to port 8090 using the provided Sigma rule.
*   Enable web server logging for unexpected requests to `/api/logs`, `/api/enter`, and `/api/command` endpoints originating from localhost, as detected by the provided Sigma rule.
