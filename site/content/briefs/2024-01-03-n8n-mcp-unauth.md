---
title: n8n-mcp Unauthenticated Access and Information Disclosure Vulnerability
slug: 2024-01-03-n8n-mcp-unauth
description: The n8n-mcp HTTP server had improper authentication in several endpoints, and the health check endpoint leaked sensitive metadata, allowing unauthenticated attackers with network access to disrupt MCP sessions and gather information for further attacks.
date: "2024-01-03T18:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - n8n-mcp
  - unauthenticated access
  - information disclosure
  - network
vendors:
  - n8n
products:
  - n8n-mcp
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Host Information
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-75hx-xj24-mqrw
rules:
  - title: Detect n8n-mcp Unauthenticated Health Check Access
    description: Detects attempts to access the n8n-mcp health check endpoint without authentication, indicating potential exploitation of the information disclosure vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1592.002
    data_sources:
      - webserver
      - linux
  - title: Detect n8n-mcp Unauthenticated Session Endpoint Access
    description: Detects attempts to access n8n-mcp session endpoints without valid authentication.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1592.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

n8n-mcp, a message communication protocol, versions 2.47.5 and earlier contained vulnerabilities related to unauthenticated access. Specifically, several HTTP transport endpoints lacked proper authentication, allowing unauthorized access to MCP sessions. Additionally, the health check endpoint exposed sensitive operational metadata without requiring any credentials. This exposure allows an unauthenticated attacker with network access to the n8n-mcp HTTP server to potentially disrupt active MCP sessions and gather information that could be leveraged for further malicious activities. The vulnerability was resolved in version 2.47.6. The vendor recommends upgrading immediately, and if that is not possible, they recommend implementing network restrictions.

## Attack Chain

1.  Attacker gains network access to the n8n-mcp HTTP server.
2.  Attacker sends an HTTP request to an MCP session endpoint without providing Bearer authentication.
3.  The server, in versions <= 2.47.5, improperly processes the request without proper authentication checks.
4.  Attacker is able to interact with and potentially disrupt active MCP sessions due to the lack of authentication.
5.  Alternatively, the attacker sends an HTTP request to the health check endpoint.
6.  The server responds with sensitive operational metadata, which could include information about the system's configuration and status.
7.  Attacker analyzes the exposed metadata to identify potential weaknesses or vulnerabilities in the system.
8.  Attacker uses gathered information to formulate further attacks against the n8n-mcp instance or related systems.

## Impact

Successful exploitation of this vulnerability could allow an unauthenticated attacker to disrupt active MCP sessions, potentially impacting the availability and integrity of the n8n system. Furthermore, the exposure of sensitive operational metadata through the health check endpoint could aid attackers in reconnaissance, facilitating subsequent attacks. The severity is high due to the potential for session disruption and information leakage. While the exact number of affected instances is unknown, all deployments of n8n-mcp versions 2.47.5 and earlier are vulnerable if running in HTTP mode and exposed to untrusted networks.

## Recommendation

*   Upgrade n8n-mcp to version 2.47.6 or later to remediate the vulnerability as documented in the advisory ([https://github.com/advisories/GHSA-75hx-xj24-mqrw](https://github.com/advisories/GHSA-75hx-xj24-mqrw)).
*   If upgrading is not immediately feasible, restrict network access to the n8n-mcp HTTP server using firewall rules, reverse proxy IP allowlists, or a VPN, as suggested in the advisory.
*   Deploy the Sigma rule "Detect n8n-mcp Unauthenticated Health Check Access" to monitor for attempts to access the health check endpoint without authentication.
*   If possible, use stdio mode (`MCP_MODE=stdio`) instead of HTTP mode as a temporary workaround, as the stdio transport is not affected as per the advisory.
