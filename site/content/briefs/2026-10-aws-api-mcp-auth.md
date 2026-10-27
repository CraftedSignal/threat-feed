---
brief_id: brief-2026-10-27-aws-api-mcp-auth
event_id: brief-2026-10-27-aws-api-mcp-auth
revision: 1
activity_at: "2026-10-27T20:04:47Z"
title: 'AWS API MCP Server: OAuth token audience validation vulnerability (CVE-2026-115413)'
slug: 2026-10-aws-api-mcp-auth
description: AWS API MCP Server before version 1.6.0 lacks proper OAuth audience validation, potentially allowing a local user to run AWS operations with the server's configured credentials via an access token issued to another application.
date: "2026-10-27T20:04:47Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
products:
  - AWS API MCP Server (< 1.6.0)
cves:
  - id: CVE-2026-115413
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115413
---

AWS API MCP Server before version 1.6.0 does not perform token audience validation in the OAuth authentication mode. This may allow a local user to execute AWS operations using the server's configured AWS credentials by providing an access token issued to another application by the same identity provider.

To remediate this issue, users should upgrade to version 1.6.0 and configure the expected token audience or client ID for the server.
