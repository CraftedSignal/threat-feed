---
title: 'Tilt: Cross-site WebSocket Hijacking Vulnerability (CVE-2026-55883)'
slug: 2026-06-tilt-websocket-hijacking
description: An attacker can exploit CVE-2026-55883, a Cross-site WebSocket Hijacking vulnerability in Tilt versions 0.24.0 through 0.37.3, by acquiring an unauthenticated CSRF token or bypassing Origin header checks, to establish a WebSocket connection to a network-exposed Tilt HUD and exfiltrate sensitive developer session state, Tiltfile contents, and resource statuses.
date: "2026-06-19T13:56:14Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - websocket
  - hijacking
  - CVE
  - Tilt
  - developer-tool
  - web-vulnerability
vendors:
  - Tilt Development
products:
  - Tilt (0.24.0-0.37.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://github.com/advisories/GHSA-6m68-r693-78qx
rules:
  - title: Detect Tilt WebSocket Token Request (CVE-2026-55883)
    description: Detects CVE-2026-55883 exploitation — HTTP GET request to /api/websocket_token to acquire the CSRF token, indicating an attacker attempting to initiate WebSocket hijacking.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Suspicious Tilt HUD WebSocket Connection (CVE-2026-55883)
    description: Detects CVE-2026-55883 exploitation — WebSocket upgrade request to /ws/view endpoint containing a 'csrf' query parameter, suggesting an attempt to hijack the Tilt HUD stream.
    platform: sigma
    severity: high
    tactics:
      - collection
      - initial_access
    techniques:
      - T1005
      - T1190
    data_sources:
      - webserver
  - title: Detect Unusual Network Connections to Tilt HUD Port (CVE-2026-55883)
    description: Detects CVE-2026-55883 exploitation — Monitors for network connections to the default Tilt HUD port 10350 from unexpected source IPs, which could indicate a reconnaissance or exploitation attempt against an exposed Tilt instance.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
rules_count: 3
---

A significant Cross-site WebSocket Hijacking (CSWSH) vulnerability, identified as CVE-2026-55883, affects Tilt, a popular developer tool for managing local Kubernetes development environments. This flaw impacts Tilt versions 0.24.0 through 0.37.3. The vulnerability stems from two issues: an unauthenticated endpoint (`/api/websocket_token`) that readily provides the `websocketCSRFToken`, and a WebSocket upgrader that accepts connections from clients omitting the `Origin` header. An attacker can combine these weaknesses to bypass intended security controls. If a Tilt HUD instance is configured to bind to a non-loopback address (e.g., `0.0.0.0`) and is network-reachable on its default port (10350), an adversary can leverage this to open the HUD WebSocket stream and compromise sensitive developer data, including session state, `Tiltfile` contents, and real-time resource statuses, thereby undermining the integrity of the development environment.

## Attack Chain

1.  **Reconnaissance & Initial Access**: An attacker identifies a vulnerable Tilt HUD instance (versions 0.24.0-0.37.3) that is configured to bind to a non-loopback address (e.g., `0.0.0.0`) and is network-reachable on its default port `10350`.
2.  **CSRF Token Acquisition**: The attacker sends an unauthenticated HTTP GET request to the exposed Tilt instance's `/api/websocket_token` endpoint.
3.  **Token Response**: The vulnerable Tilt instance responds with the `websocketCSRFToken` in `text/plain` format.
4.  **WebSocket Connection Initiation (Option 1 - CSRF Token)**: Using the obtained `websocketCSRFToken`, the attacker crafts and sends a WebSocket upgrade request to `/ws/view?csrf=<token>`.
5.  **WebSocket Connection Initiation (Option 2 - Origin Bypass)**: Alternatively, the attacker sends a WebSocket upgrade request to `/ws/view` while intentionally omitting the `Origin` HTTP header, exploiting the server's fallback logic for same-origin checks.
6.  **Successful WebSocket Upgrade**: The vulnerable Tilt instance accepts the WebSocket connection, establishing a communication channel with the attacker.
7.  **Data Collection & Exfiltration**: The attacker receives and exfiltrates a continuous stream of sensitive developer session data, `Tiltfile` contents, and real-time resource statuses over the established WebSocket connection.

## Impact

Successful exploitation of CVE-2026-55883 allows an attacker to gain unauthorized access to critical information within a developer's environment. This includes sensitive intellectual property like `Tiltfile` contents (which can reveal build processes, dependencies, and configurations), real-time status updates of deployed applications, and potentially credentials or other session-related data if stored or reflected in the HUD stream. Organizations using Tilt in network-exposed configurations are at risk of data breaches, compromise of their development pipeline, and loss of confidential information, severely impacting development security and operational integrity.

## Recommendation

1.  Upgrade Tilt to a patched version (0.37.4 or later) immediately to remediate CVE-2026-55883.
2.  Ensure all Tilt HUD instances are configured to bind exclusively to loopback addresses (e.g., `127.0.0.1`) by omitting the `--host` flag or unsetting `TILT_HOST`, thereby restricting network reachability.
3.  Deploy the "Detect Tilt WebSocket Token Request (CVE-2026-55883)" Sigma rule to your SIEM to identify attempts at acquiring the `websocketCSRFToken` via `/api/websocket_token` in web server logs.
4.  Deploy the "Detect Suspicious Tilt HUD WebSocket Connection (CVE-2026-55883)" Sigma rule to your SIEM to alert on WebSocket upgrade requests to `/ws/view` containing `csrf` parameters, indicating potential exploitation attempts.
5.  Monitor network activity for unusual inbound connections to TCP port `10350` to identify potentially exposed or compromised Tilt HUD instances.
