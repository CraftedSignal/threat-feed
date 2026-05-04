---
title: Signal K Server WebSocket Login Brute-Force Vulnerability
slug: 2024-01-signalk-brute-force
description: The Signal K server's WebSocket login endpoint lacks rate limiting, allowing attackers to bypass HTTP rate limiting by opening a WebSocket connection and attempting unlimited password guesses.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - brute-force
  - websocket
vendors:
  - Signal K
products:
  - signalk-server (<= 2.24.0)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
references:
  - https://github.com/advisories/GHSA-vmfm-ch9h-5c7g
rules:
  - title: Detect High Volume SignalK WebSocket Login Attempts
    description: Detects a high number of Signal K WebSocket login attempts from a single source IP address, indicating a potential brute-force attack.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110.001
    data_sources:
      - network_connection
      - windows
rules_count: 1
---

Signal K server versions 2.24.0 and earlier are vulnerable to credential brute-forcing via the WebSocket protocol. The vulnerability stems from the lack of rate limiting on the WebSocket login endpoint (`/signalk/v1/stream`), which allows attackers to bypass the existing HTTP rate limiting mechanism. By establishing a WebSocket connection, an attacker can send an unlimited number of login attempts, effectively bypassing the intended rate limiting defense of 100 attempts per 10 minutes on the HTTP login endpoints. This makes it feasible to conduct dictionary attacks and potentially gain unauthorized access to Signal K servers. Signal K servers are commonly deployed on boat networks.

## Attack Chain

1.  Attacker identifies a vulnerable Signal K server.
2.  Attacker establishes a WebSocket connection to `ws://server:3000/signalk/v1/stream?subscribe=none`.
3.  The server sends a hello message, confirming the connection.
4.  Attacker sends a series of login attempts via WebSocket messages using the following JSON format: `{"requestId": "1", "login": {"username": "admin", "password": "guess1"}}`.
5.  The server processes each login attempt without rate limiting.
6.  Attacker continues sending login attempts using different password guesses.
7.  If successful, the attacker gains unauthorized access to the Signal K server.

## Impact

Successful exploitation of this vulnerability allows attackers to bypass HTTP rate limiting and brute-force credentials to gain unauthorized access to Signal K servers. An attacker can achieve a brute-forcing speed of approximately 20 attempts per second, limited by the bcrypt hashing algorithm. A dictionary attack with 10,000 words can be completed in approximately 8 minutes over a single connection. Since Signal K servers are commonly deployed on boat networks, successful exploitation can lead to unauthorized access to sensitive maritime data.

## Recommendation

*   Monitor network connections to Signal K servers for unusually high rates of WebSocket login attempts. Create a detection rule that triggers when a single IP address sends more than 5 login attempts per second via the WebSocket protocol.
*   Deploy the Sigma rule `Detect High Volume SignalK WebSocket Login Attempts` to identify potential brute-force attacks against Signal K servers.
*   Upgrade Signal K servers to a patched version that includes rate limiting on the WebSocket login endpoint.
