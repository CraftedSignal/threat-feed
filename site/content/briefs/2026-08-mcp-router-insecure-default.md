---
title: Unauthenticated Remote Access Vulnerability in mcp-router CLI
slug: 2026-08-mcp-router-insecure-default
description: The mcp-router CLI versions prior to 0.6.3 default to binding the MCP aggregator service to all network interfaces without mandatory authentication, exposing fronted MCP servers to unauthorized remote access.
date: "2026-08-27T19:08:54Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
products:
  - mcp-router
cves:
  - id: CVE-2026-81094
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-81094
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade mcp-router to 0.6.3 or higher.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-81094 remediation requires version 0.6.3.
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to mcp-router ports.
      owner: IT Operations
      addresses: CVE-2026-81094
      evidence: Service binds to all interfaces by default in affected versions.
---

The mcp-router CLI tool contains a significant configuration vulnerability (CVE-2026-81094) in how it handles the 'serve' command. In versions prior to 0.6.3, the aggregator service defaults to binding to all network interfaces (0.0.0.0) on a fixed port rather than the local loopback interface. Furthermore, the application does not enforce authentication tokens by default. If an operator starts the tool using default settings, the MCP aggregator and all downstream MCP servers it orchestrates are exposed to any party with network reachability to the host. This effectively allows unauthorized actors to interface with, query, or potentially influence data processed by the MCP aggregator. The vulnerability was remediated in release 0.6.3, which forces a loopback bind by default and enforces token-based authentication when non-loopback addresses are specified.

## Impact

Successful exploitation allows an unauthenticated attacker to interact with the mcp-router CLI, enabling unauthorized access to sensitive MCP-managed resources. Organizations using versions earlier than 0.6.3 in production environments are at risk of lateral movement or information disclosure if the host is reachable from untrusted network segments.

## Recommendation

- Upgrade mcp-router to version 0.6.3 or higher immediately to enforce secure network binding and mandatory authentication.
- Audit existing deployments of mcp-router to identify instances bound to non-loopback interfaces.
- Implement network access control lists (ACLs) to restrict access to the mcp-router listening port to authorized management hosts only.
