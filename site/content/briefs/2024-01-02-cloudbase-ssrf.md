---
title: TencentCloudBase CloudBase-MCP Server-Side Request Forgery Vulnerability (CVE-2026-7221)
slug: 2024-01-02-cloudbase-ssrf
description: A server-side request forgery vulnerability exists in TencentCloudBase CloudBase-MCP up to version 2.17.0, allowing remote attackers to manipulate the `req.body.url` argument in the `openUrl` function of `mcp/src/interactive-server.ts` to conduct SSRF attacks.
date: "2024-01-02T12:00:00Z"
severities:
  - high
tags:
  - SSRF
  - CVE-2026-7221
  - TencentCloudBase
vendors:
  - TencentCloudBase
products:
  - CloudBase-MCP
cves:
  - id: CVE-2026-7221
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7221
rules:
  - title: CloudBase-MCP SSRF Attempt via openUrl API
    description: Detects potential SSRF attempts by monitoring requests to the openUrl API endpoint with suspicious URLs.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
  - title: CloudBase-MCP SSRF Attempt via openUrl API - External IP in URL
    description: Detects potential SSRF attempts by monitoring requests to the openUrl API endpoint with suspicious URLs containing external IP addresses.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A server-side request forgery (SSRF) vulnerability has been identified in TencentCloudBase CloudBase-MCP, affecting versions up to 2.17.0. The vulnerability resides in the `openUrl` function within the `mcp/src/interactive-server.ts` file. This flaw enables a remote attacker to manipulate the `req.body.url` argument passed to the open-url API Endpoint, forcing the server to make requests to arbitrary internal or external resources. Successful exploitation could lead to information disclosure…
