---
title: FUXA Pre-auth RCE via Path Manipulation and Configuration Injection
slug: 2026-05-fuxa-rce
description: A critical vulnerability in FUXA (versions 1.2.11 to 1.3.0) allows an unauthenticated remote attacker to achieve remote code execution as root by bypassing authentication checks on protected Node-RED endpoints using path manipulation.
date: "2026-05-26T23:44:32Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - rce
  - authentication-bypass
vendors:
  - frangoteam
products:
  - fuxa
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-p69w-mmfv-xrfj
  - CVE-2026-43945
rules:
  - title: Detect CVE-2026-43945 Exploitation Attempt
    description: Detects CVE-2026-43945 exploitation attempt — HTTP request to /nodered/* with socket.io in the query string
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-43945 Exploitation Attempt - POST Request
    description: Detects CVE-2026-43945 exploitation attempt via POST request to /nodered/* endpoint with socket.io in the query
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

FUXA, a SCADA platform, is vulnerable to a pre-authentication remote code execution (RCE) flaw. This vulnerability, impacting versions 1.2.11 through 1.3.0, allows an unauthenticated attacker to bypass authentication on protected `/nodered/*` endpoints. The root cause is a path confusion issue in the authentication middleware that relies on `req.originalUrl` for routing decisions. By appending `?x=/socket.io` to administrative requests, the middleware is tricked into treating the request as a public WebSocket handshake, bypassing secureEnabled and nodeRedAuthMode checks entirely. Successful exploitation grants access to Node-RED administrative endpoints, potentially leading to RCE depending on the Node-RED configuration and installed nodes. This vulnerability is tracked as CVE-2026-43945.

## Attack Chain

1.  Attacker sends a crafted HTTP request to the FUXA server.
2.  The request targets a protected `/nodered/*` endpoint.
3.  The request includes a query parameter designed to exploit the path confusion vulnerability, such as `?x=/socket.io`.
4.  The FUXA server's authentication middleware incorrectly identifies the request as a public WebSocket handshake due to the flawed `url.includes('/socket.io')` check.
5.  The security checks for `secureEnabled` and `nodeRedAuthMode` are bypassed.
6.  The attacker gains unauthorized access to the Node-RED administrative interface.
7.  The attacker leverages Node-RED's capabilities to execute arbitrary code on the server, depending on the configuration and installed nodes.
8.  The attacker achieves remote code execution as root within the container context.

## Impact

Successful exploitation of CVE-2026-43945 allows an unauthenticated attacker to gain full control over the SCADA server. This can lead to interception of industrial data (MQTT/OPC-UA), manipulation of PLC tags, and the ability to pivot into the internal OT network. The vulnerability can result in complete system compromise and significant disruption to industrial processes.

## Recommendation

*   Apply the vendor-supplied patch to upgrade FUXA to a version >= 1.3.1 to remediate CVE-2026-43945.
*   Deploy the Sigma rule "Detect CVE-2026-43945 Exploitation Attempt" to your SIEM to detect exploitation attempts.
*   Monitor web server logs for requests containing the `/socket.io` string in the query parameters targeting `/nodered/*` endpoints.
*   Review Node-RED configurations to minimize the risk of RCE via privileged or command-execution capable nodes, if Node-RED is enabled.
