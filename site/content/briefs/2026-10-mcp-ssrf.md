---
title: SSRF Vulnerability in Model Context Protocol Server Packages
slug: 2026-10-mcp-ssrf
description: A server-side request forgery (SSRF) vulnerability in the Fetch Tool component of the Model Context Protocol server packages allows remote attackers to perform unauthorized requests.
date: "2026-10-02T04:22:17Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:modelcontextprotocol:mcp-server-fetch:*:*:*:*:*:*:*:*
  - cpe:2.3:a:modelcontextprotocol:mcp-server-everything:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - ssrf
vendors:
  - modelcontextprotocol
products:
  - mcp-server-fetch (<= 2026.6.4)
  - mcp-server-everything (<= 2026.6.4)
cves:
  - id: CVE-2026-104120
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104120
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Inventory all instances of mcp-server-fetch and mcp-server-everything
      owner: IT Operations
      due: 24h
  mitigation_plan:
    - priority: immediate
      action: Restrict egress traffic from MCP server hosts to sensitive internal/cloud IP ranges
      owner: IT Operations
      addresses: CVE-2026-104120
---

A server-side request forgery (SSRF) vulnerability has been identified in the Fetch Tool component within the Model Context Protocol (MCP) packages `mcp-server-fetch` and `mcp-server-everything` in versions up to 2026.6.4. The vulnerability resides in the `fetch_url` function of `mcp_server_fetch/server.py`. By manipulating the `url` or `path` argument, an unauthenticated remote attacker can force the server to perform unauthorized outbound HTTP requests. This could allow an attacker to probe internal network services, access metadata endpoints in cloud environments, or bypass network-level security controls. While the vulnerability has been publicly disclosed and exploitation is possible, a fix is currently pending acceptance via pull request. Defenders should audit applications utilizing these MCP servers for unexpected outbound traffic patterns originating from the server process.

## Impact

Successful exploitation allows remote attackers to perform server-side request forgery. This impact may include the exfiltration of sensitive data from internal services, unauthorized access to private cloud metadata services, and reconnaissance of the internal network architecture.

## Recommendation

1. Review applications utilizing `mcp-server-fetch` or `mcp-server-everything` for any usage of the Fetch Tool component and verify versioning against the vulnerable range (<= 2026.6.4).
2. Implement strict egress filtering on the host environment to prevent the MCP server from reaching sensitive internal segments or cloud metadata endpoints.
3. Monitor web server logs and application logs for unusual URL or path parameters passed to the Fetch Tool's entry points.
