---
title: Unauthenticated SQL Execution and RCE in MySQL MCP Server via SSE Transport
slug: 2026-09-mysql-mcp-server-rce
description: The mysql_mcp_server package (v < 0.4.2) fails to implement security protections in SSE transport mode, enabling unauthenticated attackers to perform arbitrary SQL execution, data exfiltration, and potential remote code execution.
date: "2026-09-12T00:57:18Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:mysql_mcp_server_project:mysql_mcp_server:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - sql-injection
  - mcp
products:
  - mysql_mcp_server (< 0.4.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Internet-wide scanning has identified 25 publicly reachable SSE instances of this project.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Any network attacker can invoke execute_sql to run arbitrary SQL without credentials.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-rqfv-2mw9-78g2
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit external exposure of services listening on ports associated with MCP implementations
      owner: SOC
      due: 24h
      evidence: 25 publicly reachable SSE instances of this project were identified.
  mitigation_plan:
    - priority: immediate
      action: Upgrade mysql_mcp_server to v0.4.2 or later
      owner: IT Operations
      addresses: CVE-2026-59971
      evidence: 'Released in v0.4.2: DNS-rebinding protection is now enabled.'
---

The `mysql_mcp_server` package (prior to v0.4.2) contains a critical security vulnerability when configured to use the Server-Sent Events (SSE) transport mode. Due to the failure to instantiate `SseServerTransport` with `security_settings`, the application lacks essential protections, including DNS-rebinding prevention, CORS middleware, and TrustedHost validation. Furthermore, the application exposes unauthenticated endpoints (`/`, `/sse`, and `/messages/`) and binds to `0.0.0.0` by default.

An unauthenticated remote attacker can exploit this configuration to execute arbitrary SQL commands against the database backend. If the database user is configured with `FILE` privileges, this vulnerability enables arbitrary file read and write operations, which can be leveraged to achieve remote code execution by dropping a malicious web shell. Instances exposed to the internet are at high risk, as are local instances susceptible to browser-based DNS-rebinding attacks. 25 publicly reachable instances have already been identified.

## Attack Chain

1. Attacker identifies an exposed MySQL MCP Server instance running with `MCP_TRANSPORT=sse` on a public interface (0.0.0.0).
2. Attacker sends an unauthenticated HTTP POST request to the `/messages` endpoint.
3. The request includes a JSON payload containing a malicious SQL query within the `execute_sql` tool call.
4. The server receives the request and, lacking authentication middleware, processes the tool call directly.
5. The application invokes `cursor.execute(query)` using the attacker-supplied, unsanitized SQL.
6. The database executes the query, returning results to the attacker or performing file system operations (e.g., `INTO OUTFILE`).
7. Attacker successfully achieves data exfiltration or writes a malicious payload to the host system.

## Impact

Successful exploitation allows for full database exfiltration, modification, and potential system compromise. Attackers can leverage MySQL's `FILE` privileges to read sensitive files or write executable files (web shells) to the underlying server. Evidence suggests 25 publicly exposed instances are currently reachable, posing an immediate risk to environments utilizing this server for LLM-integrated database tasks.

## Recommendation

1. Upgrade `mysql_mcp_server` to version 0.4.2 or later immediately to enable mandatory security settings.
2. Configure the server to bind to `127.0.0.1` rather than `0.0.0.0` if remote access is not required.
3. Ensure the database user assigned to the MCP server follows the principle of least privilege, specifically revoking `FILE` access if not strictly required.
4. Implement network-level access control (firewall or VPN) to restrict access to the SSE transport interface.
