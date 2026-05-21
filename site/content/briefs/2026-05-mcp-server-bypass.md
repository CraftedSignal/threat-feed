---
title: MCP Server Kubernetes Tool Access Control Bypass (CVE-2026-46519)
slug: 2026-05-mcp-server-bypass
description: MCP Server Kubernetes versions before 3.6.0 have an access control bypass vulnerability (CVE-2026-46519) where tool access controls are enforced only at the discovery layer, allowing authenticated clients to invoke any Kubernetes tool regardless of configured restrictions, potentially leading to cluster compromise.
date: "2026-05-21T20:34:49Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - access-control-bypass
  - privilege-escalation
  - kubernetes
  - cloud
vendors:
  - Manifold Security
products:
  - mcp-server-kubernetes (< 3.6.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1213
    technique_name: Exploitation of Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-cr22-wjx7-2w6m
  - CVE-2026-46519
rules:
  - title: Detect CVE-2026-46519 Exploitation — MCP Server Kubernetes Tool Call Bypass
    description: Detects CVE-2026-46519 exploitation — attempts to call restricted Kubernetes tools via the /mcp endpoint.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1213
    data_sources:
      - webserver
  - title: Detect MCP Server Kubernetes /mcp POST Request
    description: Detects POST request to the /mcp endpoint.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    data_sources:
      - webserver
rules_count: 2
---

MCP Server Kubernetes is vulnerable to an access control bypass that allows authenticated users to execute any Kubernetes tool regardless of the configured restriction mode. The vulnerability lies in the `tools/call` endpoint, which doesn't enforce the same filtering logic as the `tools/list` endpoint. This means an attacker with network access to the MCP server, even with limited permissions (e.g., `kubectl_get`), can invoke more sensitive tools like `kubectl_delete`, `exec_in_pod`, `kubectl_generic`, and `node_management`. The issue was present in versions prior to v3.6.0. This bypass is particularly dangerous in multi-client HTTP deployment scenarios, where operators rely on tool restrictions to enforce least-privilege access. Exploitation of this vulnerability can lead to full cluster compromise if the MCP server runs with `cluster-admin` privileges.

## Attack Chain

1.  Attacker gains network access to the MCP server's HTTP endpoint.
2.  Attacker authenticates to the MCP server using a valid `MCP_AUTH_TOKEN` or `X-MCP-AUTH` header.
3.  Attacker discovers available tools via the `tools/list` endpoint. The returned list may be restricted based on configured environment variables.
4.  Attacker crafts a `tools/call` request with the name of a restricted tool (e.g., `kubectl_delete`).
5.  Attacker includes the necessary arguments for the chosen tool in the `params` field of the request.
6.  Attacker sends the crafted `tools/call` request to the MCP server's HTTP endpoint.
7.  The MCP server executes the requested tool without validating if the authenticated user has permission to use it.
8.  The attacker achieves the intended malicious action (e.g., deleting a pod).

## Impact

Successful exploitation of this vulnerability allows an attacker or misconfigured AI agent to bypass intended access controls and execute arbitrary Kubernetes commands. The impact scales with the permissions of the Kubernetes service account used by the MCP server. In environments where the MCP server runs with `cluster-admin` privileges, this can lead to full cluster compromise, including unauthorized data access, modification, and deletion. This vulnerability affected users relying on tool restriction environment variables to enforce least-privilege access, potentially leading to privilege escalation and unauthorized actions within the Kubernetes cluster.

## Recommendation

*   Upgrade to `mcp-server-kubernetes` version 3.6.0 or later to remediate CVE-2026-46519.
*   Monitor HTTP requests to the `/mcp` endpoint for `tools/call` methods attempting to invoke sensitive Kubernetes tools like `kubectl_delete`, `exec_in_pod`, `kubectl_generic`, and `node_management` (see example Sigma rule below).
*   Review and restrict the permissions of the Kubernetes service account used by the MCP server to adhere to the principle of least privilege.
*   Implement network segmentation to limit access to the MCP server's HTTP endpoint only to authorized clients.
