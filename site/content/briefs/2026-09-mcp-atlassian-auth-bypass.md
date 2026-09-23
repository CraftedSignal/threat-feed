---
title: Authentication Bypass in mcp-atlassian HTTP Transport
slug: 2026-09-mcp-atlassian-auth-bypass
description: The mcp-atlassian package contains an authentication bypass vulnerability (CVE-2026-77244) that allows unauthenticated network-adjacent attackers to execute tools using the operator's Jira and Confluence credentials.
date: "2026-09-23T01:54:36Z"
lastmod: "2026-09-23T01:57:54Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:atlassian:mcp-atlassian:*:*:*:*:*:*:*:*
  - cpe:2.3:a:mcp-atlassian:mcp_atlassian:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - api-security
  - atlassian
  - mcp
  - path-traversal
  - ai-security
  - exfiltration
  - vulnerability
vendors:
  - Atlassian
products:
  - mcp-atlassian (< 0.22.0)
affected_os:
  - Amazon Linux 2023
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker who reaches the HTTP transport... can send no Authorization header at all, OR send any garbage Bearer token.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The tool handlers, finding no user-supplied token, use the server's env-var credentials to call Jira / Confluence.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1005
    technique_name: Data from Local System
    evidence: An AI agent connected via MCP (or an attacker influencing that agent through prompt injection) can read any file on the host and exfiltrate it by uploading it as a Confluence page attachment.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: AWS IAM credentials (or other internal service data) are returned to the attacker.
    confidence_band: high
cves:
  - id: CVE-2026-77244
    cvss: 10
  - id: CVE-2026-27825
    cvss: 9
    epss: 0.12712
references:
  - https://github.com/advisories/GHSA-wrhw-j3f9-8vc6
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77244
  - https://github.com/advisories/GHSA-93xw-j965-9mx3
  - https://github.com/advisories/GHSA-f6pj-qv47-g96w
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77247
  - https://github.com/advisories/GHSA-6529-c226-h328
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade mcp-atlassian to 0.22.0 or higher
      owner: IT Operations
      due: 24h
      evidence: Source states vulnerable version is < 0.22.0
  hunt_leads:
    - lead: Search logs for JSON-RPC method calls to Jira/Confluence tools with missing or arbitrary Authorization headers
      technique_id: T1190
      data_needed:
        - Application logs from the MCP server HTTP transport
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attacker reaches HTTP transport... JiraFetcher/ConfluenceFetcher fall back to JiraConfig.from_env()
  mitigation_plan:
    - priority: immediate
      action: Bind MCP server to 127.0.0.1 and restrict access via reverse proxy
      owner: IT Operations
      addresses: CVE-2026-77244
      evidence: Source recommends binding HTTP transport to 127.0.0.1 by default
updates:
  - at: "2026-09-23T01:55:55Z"
    level: L2
    summary: added coverage for mcp-atlassian (< 0.22.0)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-93xw-j965-9mx3
  - at: "2026-09-23T01:56:03Z"
    level: L2
    summary: added coverage for mcp-atlassian (< 0.22.0)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-f6pj-qv47-g96w
  - at: "2026-09-23T01:57:54Z"
    level: L2
    summary: added coverage for mcp-atlassian (< 0.22.0)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-6529-c226-h328
---

The `mcp-atlassian` Python package is vulnerable to a critical authentication bypass (CVE-2026-77244) due to improper validation in the `AtlassianOpaqueTokenVerifier` utility. The implementation of `verify_token()` explicitly accepts any non-empty string as a valid credential. Furthermore, the `mcp-atlassian` HTTP transport defaults to disabled OAuth proxy authentication and fails to reject requests lacking an `Authorization` header.

When deployed in the standard pattern (storing `JIRA_API_TOKEN` or `CONFLUENCE_API_TOKEN` in environment variables), the MCP server fails to challenge unauthenticated requests. Instead, it proceeds to invoke Jira/Confluence tool handlers using the server-side environment variables. An attacker with network reach to the MCP server can send arbitrary requests - or no credentials at all - to perform unauthorized operations on the operator's Atlassian instance. This vulnerability is significant because it grants attackers the full API privileges of the server operator, including read and write access to all accessible Jira issues and Confluence pages.

## Attack Chain

1. Attacker performs network discovery to identify an `mcp-atlassian` HTTP transport instance reachable on the network (e.g., via default Docker port mappings or misconfigured cloud load balancers).
2. Attacker crafts a JSON-RPC request targeting the `/mcp` endpoint with the desired tool execution parameters (e.g., `jira_get_issue` or `jira_add_comment`).
3. The request is transmitted to the server without an `Authorization` header, or with a dummy "Bearer" token.
4. `UserTokenMiddleware._parse_auth_header` processes the request; seeing no valid client token, it passes the request context to the internal handlers without rejection.
5. The `AtlassianOpaqueTokenVerifier` receives the request; if a dummy token is provided, it is accepted by the logic that validates only that the string is non-empty.
6. The `JiraFetcher` or `ConfluenceFetcher` detects the absence of a user-supplied token in the scope state and initiates `JiraConfig.from_env()`.
7. The server retrieves the operator's `JIRA_API_TOKEN` or `CONFLUENCE_API_TOKEN` from the process environment variables.
8. The tool execution is performed against the Atlassian cloud backend using the operator's identity, resulting in data exfiltration, unauthorized modification, or persistent access creation.

## Impact

Successful exploitation grants an attacker full read and write access to the operator's Jira and Confluence instances. Because all API calls are made using the operator's legitimate credentials, the attacker's actions appear as authenticated operator activity in Atlassian audit logs, facilitating anti-forensics and shifting blame to the victim. Furthermore, attackers can leverage the MCP server to pivot, exfiltrate sensitive data stored in attachments or documentation, and create persistent backdoors via Jira webhooks or automation rules.

## Recommendation

1. Upgrade the `mcp-atlassian` package to version 0.22.0 or later immediately to patch CVE-2026-77244.
2. For deployments not using OAuth proxy, implement strict network-level access control (e.g., firewall rules or mTLS) to restrict access to the MCP server to authorized users only.
3. If version 0.22.0 is not immediately available, disable public exposure of the HTTP transport by binding the service to `127.0.0.1` and utilizing a secure reverse proxy (e.g., Nginx or Traefik) that enforces authentication before forwarding traffic to the MCP server.
4. Audit Jira and Confluence audit logs for anomalous tool execution patterns or unauthorized modification of issues and automation rules originating from the host IP of the MCP server.
