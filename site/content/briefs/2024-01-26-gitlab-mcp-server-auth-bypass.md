---
title: GitLab MCP Server Unauthenticated Access via SSE Transport
slug: 2024-01-26-gitlab-mcp-server-auth-bypass
description: The @yoda.digital/gitlab-mcp-server's SSE transport lacks authentication and uses wildcard CORS, enabling unauthenticated attackers to execute arbitrary GitLab API calls using the operator's GitLab PAT, including destructive operations.
date: "2024-01-26T18:47:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - gitlab
  - auth-bypass
  - sse
  - cors
  - vulnerability
vendors:
  - GitLab
products:
  - '@yoda.digital/gitlab-mcp-server (< 0.6.0)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1213
    technique_name: Exploitation of Privilege Escalation
references:
  - https://github.com/advisories/GHSA-8jr5-6gvj-rfpf
rules:
  - title: Detect GitLab MCP Server Unauthenticated SSE Connection
    description: Detects connections to the `/sse` endpoint of the GitLab MCP Server without authentication, indicating a potential attempt to exploit CVE-2026-44895.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect GitLab MCP Server Unauthenticated API Call
    description: Detects unauthenticated calls to the `/messages` endpoint of the GitLab MCP Server, indicating potential exploitation of CVE-2026-44895 via the SSE transport.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - webserver
rules_count: 2
---

The `@yoda.digital/gitlab-mcp-server` exposes an unauthenticated SSE HTTP transport that allows anyone who can reach the server's port to execute arbitrary GitLab API calls with the operator's `GITLAB_PERSONAL_ACCESS_TOKEN`. This vulnerability exists because the server does not require any authentication for the `/sse` and `/messages` endpoints and uses a wildcard CORS policy, effectively allowing any website visited by the operator to interact with the server. This allows attackers to perform destructive operations such as deleting repositories or pushing malicious files. The issue was identified in commit `80a7b4cf3fba6b55389c0ef491a48190f7c8996a` of the `mcp-gitlab-server` and affects versions prior to 0.6.0.

## Attack Chain

1. The attacker identifies a vulnerable `@yoda.digital/gitlab-mcp-server` instance running with `USE_SSE=true` enabled.
2. The attacker crafts a malicious web page that, when visited by the operator, attempts to connect to the `/sse` endpoint of the GitLab MCP server.
3. Due to the wildcard CORS policy (`Access-Control-Allow-Origin: *`), the browser allows the cross-origin request from the malicious page to succeed.
4. The server establishes an SSE connection and provides the attacker with a session ID in the form of `/messages?sessionId=<UUID>`.
5. The attacker's malicious web page sends a POST request to the `/messages?sessionId=<UUID>` endpoint, specifying a `tools/call` method with a desired GitLab API function (e.g., `delete_repository`, `push_files`).
6. The server receives the unauthenticated request and, using the operator's `GITLAB_PERSONAL_ACCESS_TOKEN`, executes the requested GitLab API call.
7. The attacker successfully deletes repositories, pushes malicious files, or modifies repository settings on the targeted GitLab instance.
8. The attacker achieves their objective, such as compromising the integrity of the GitLab instance or exfiltrating sensitive data.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to perform arbitrary actions on a GitLab instance using the permissions of the operator's `GITLAB_PERSONAL_ACCESS_TOKEN`. This includes deleting repositories, pushing malicious code, and modifying repository settings. The impact is significant as it allows complete compromise of the targeted GitLab instance. The vulnerability affects any instance where the `@yoda.digital/gitlab-mcp-server` is running with `USE_SSE=true` and is network accessible, or when the operator visits a malicious webpage while running the server.

## Recommendation

*   As a short-term mitigation, if using SSE, immediately set the `MCP_GITLAB_AUTH_TOKEN` environment variable and validate that the server is checking this token on every request as suggested in the advisory to prevent unauthenticated access.
*   Limit network exposure by ensuring that the server is bound to `127.0.0.1` unless there's a specific requirement for network accessibility. Configure the `MCP_GITLAB_HOST` variable and use the `CORS_ORIGINS` allowlist as described in the advisory.
*   Upgrade to version 0.6.0 or later of `@yoda.digital/gitlab-mcp-server` when available to obtain the official fix and ensure that the SAML/OAuth3 authentication mechanisms described in the README are implemented to secure the SSE transport.
*   Deploy the Sigma rule "Detect GitLab MCP Server Unauthenticated SSE Connection" to detect connections to the `/sse` endpoint, indicating potential exploitation attempts.
*   Deploy the Sigma rule "Detect GitLab MCP Server Unauthenticated API Call" to detect unauthenticated calls to the `/messages` endpoint, indicating exploitation via the SSE transport.
