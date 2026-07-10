---
title: Unauthenticated Remote Takeover of Nginx-UI via MCP Endpoint
slug: 2024-01-nginx-ui-takeover
description: Nginx-UI is vulnerable to unauthenticated remote takeover due to a missing authentication check on the `/mcp_message` endpoint, allowing attackers to invoke MCP tools without authentication, leading to arbitrary nginx configuration modification, traffic interception, service disruption, configuration exfiltration, and credential harvesting; the default empty IP whitelist allows access from any network attacker.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - nginx-ui
  - nginx
  - unauthenticated
  - remote-takeover
  - CVE-2026-33032
vendors:
  - Nginx-UI
products:
  - Nginx-UI
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505.003
    technique_name: Server Software Component
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1566
    technique_name: Phishing
references:
  - https://github.com/advisories/GHSA-h6c2-x2m2-mwhf
iocs:
  - type: url
    value: http://target:9000/mcp_message
ioc_counts:
  url: 1
rules:
  - title: Detect Nginx-UI MCP Message Endpoint Usage
    description: Detects requests to the /mcp_message endpoint in Nginx-UI, which is vulnerable to unauthenticated command execution.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Nginx-UI Config Modification via MCP Message
    description: Detects requests to the /mcp_message endpoint that include 'nginx_config_add' or 'nginx_config_modify' in the request body.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - impact
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The nginx-ui MCP (Model Context Protocol) integration exposes two HTTP endpoints: `/mcp` and `/mcp_message`. While `/mcp` requires authentication, the `/mcp_message` endpoint only applies IP whitelisting - and the default IP whitelist is empty, which the middleware treats as "allow all". This vulnerability, affecting nginx-ui versions 1.99 and earlier, allows any network attacker to invoke all MCP tools without authentication via the `/mcp_message` endpoint. This includes restarting nginx, creating/modifying/deleting nginx configuration files, and triggering automatic config reloads. Successful exploitation leads to complete nginx service takeover. This is critical for defenders as it provides an unauthenticated pathway to control a critical piece of infrastructure typically fronting web applications.

## Attack Chain

1. Attacker sends an HTTP POST request to `http://target:9000/mcp_message` with a JSON payload.
2. The request bypasses authentication checks due to the missing `AuthRequired()` middleware on the `/mcp_message` endpoint.
3. The `IPWhiteList()` middleware allows all requests because the default IP whitelist is empty.
4. The request is routed to the `mcp.ServeHTTP()` handler.
5. The attacker invokes the `nginx_config_add` MCP tool to create a malicious nginx configuration file, for example in `/etc/nginx/conf.d/`.
6. The `nginx_config_add` tool writes the malicious configuration file to disk.
7. After the config is written, `nginx_config_add` attempts to reload nginx configuration via `nginx.Control(nginx.Reload)`.
8. The attacker now controls the Nginx webserver and can intercept traffic, redirect users, and exfiltrate data.

## Impact

Successful exploitation of this vulnerability grants an unauthenticated attacker complete control over the nginx service. This allows the attacker to intercept traffic, rewrite server blocks, capture credentials and session tokens, and disrupt service by writing invalid configurations. All existing nginx configurations are readable via `nginx_config_get`, potentially revealing backend topology and authentication headers. This poses a significant risk to organizations relying on nginx-ui to manage their web servers.

## Recommendation

*   Apply the patch suggested in the advisory by adding `middleware.AuthRequired()` to the `/mcp_message` route to prevent unauthenticated access (reference: GitHub advisory).
*   Deploy the Sigma rule "Detect Nginx-UI MCP Message Endpoint Usage" to identify potential exploit attempts in your environment (reference: Sigma rule below).
*   Monitor network connections to port 9000 (default nginx-ui port) for suspicious POST requests to `/mcp_message` (reference: IOC).
*   Consider changing the default IP whitelist behavior to deny-all when unconfigured (reference: GitHub advisory).
