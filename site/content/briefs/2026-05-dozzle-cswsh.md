---
title: Dozzle Cross-Site WebSocket Hijacking (CSWSH) Vulnerability
slug: 2026-05-dozzle-cswsh
description: Dozzle is vulnerable to Cross-Site WebSocket Hijacking (CSWSH) due to a permissive CheckOrigin configuration and the use of SameSite=Lax for JWT cookies, allowing attackers on the same site to gain shell access to containers even with authentication enabled, tracked as CVE-2026-44985.
date: "2026-05-11T14:08:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cswsh
  - websocket
  - authentication-bypass
vendors:
  - github.com
  - amir20
products:
  - dozzle (<= 10.5.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
references:
  - https://github.com/advisories/GHSA-j643-x8pv-8m67
  - CVE-2026-44985
rules:
  - title: Detect Dozzle CSWSH Attempt via Origin Header
    description: Detects potential Dozzle CSWSH exploitation by monitoring WebSocket connections with a non-empty Origin header from a different origin than the Dozzle server.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
  - title: Detect Dozzle Shell Access via /exec Endpoint
    description: Detects access to the /exec endpoint, which can be used to gain shell access to containers.
    platform: sigma
    severity: low
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
rules_count: 2
---

Dozzle, a real-time log viewer for Docker containers, is susceptible to a Cross-Site WebSocket Hijacking (CSWSH) vulnerability. The vulnerability exists due to the `CheckOrigin` function in the WebSocket upgrader being overridden to always return true, effectively disabling cross-origin protection. Combined with the use of `SameSite=Lax` for the JWT cookie, an attacker hosting a malicious page on the same site (e.g., a sibling subdomain or another service on localhost) can exploit this to gain unauthorized access. This allows the attacker to establish a WebSocket connection to the `/exec` or `/attach` endpoints using the victim's valid JWT cookie, granting them interactive shell access to any container the victim is authorized to access. This vulnerability, tracked as CVE-2026-44985, affects Dozzle versions up to and including 10.5.1. Even deployments with authentication properly configured are vulnerable.

## Attack Chain

1. The attacker hosts a malicious page on a domain that shares the same site as the vulnerable Dozzle instance (e.g., `attacker.example.com` if Dozzle is on `dozzle.example.com`).
2. A victim who is authenticated to Dozzle visits the attacker's page in their browser.
3. The attacker's webpage executes JavaScript that initiates a WebSocket connection to the Dozzle server, specifically targeting the `/api/hosts/{host}/containers/{id}/exec` endpoint.
4. The victim's browser automatically includes the JWT cookie in the WebSocket request because the attacker's page is on the same site and the cookie's `SameSite` attribute is set to `Lax`.
5. Dozzle's WebSocket upgrader bypasses the origin check because the `CheckOrigin` function is configured to always return `true`.
6. The Dozzle server validates the JWT cookie, authenticating the WebSocket connection as the victim.
7. The attacker now has an interactive shell session within the victim's authorized containers.
8. The attacker can then execute arbitrary commands within the container, potentially leading to sensitive information disclosure or further exploitation.

## Impact

Successful exploitation of this CSWSH vulnerability allows an attacker to execute arbitrary commands within Docker containers that the victim has access to. This can lead to the compromise of sensitive data, such as secrets, environment variables, and files stored within the containers. Furthermore, an attacker can potentially pivot to other services accessible from the container's network, potentially escalating the attack. If the Docker socket is mounted with write permissions, the attacker might even be able to escape the container and compromise the host system.

## Recommendation

*   Upgrade Dozzle to a version greater than 10.5.1 to remediate CVE-2026-44985.
*   Deploy the Sigma rule `Detect Dozzle CSWSH Attempt via Origin Header` to identify potential exploitation attempts by monitoring WebSocket connections with mismatched Origin headers, and tune it for your environment.
*   Apply the suggested fix by removing the custom `CheckOrigin` override in Dozzle's source code, reverting to the default gorilla/websocket behavior, which rejects cross-origin requests.
