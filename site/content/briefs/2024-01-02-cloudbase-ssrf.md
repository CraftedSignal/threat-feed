---
title: TencentCloudBase CloudBase-MCP Server-Side Request Forgery Vulnerability (CVE-2026-7221)
slug: 2024-01-02-cloudbase-ssrf
description: A server-side request forgery vulnerability exists in TencentCloudBase CloudBase-MCP up to version 2.17.0, allowing remote attackers to manipulate the `req.body.url` argument in the `openUrl` function of `mcp/src/interactive-server.ts` to conduct SSRF attacks.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
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

A server-side request forgery (SSRF) vulnerability has been identified in TencentCloudBase CloudBase-MCP, affecting versions up to 2.17.0. The vulnerability resides in the `openUrl` function within the `mcp/src/interactive-server.ts` file. This flaw enables a remote attacker to manipulate the `req.body.url` argument passed to the open-url API Endpoint, forcing the server to make requests to arbitrary internal or external resources. Successful exploitation could lead to information disclosure, internal network scanning, or denial-of-service. The vulnerability is publicly known and actively exploitable. Users are advised to upgrade to version 2.17.1, which includes a patch (identified as 3f678a1e7bd400cd76469d61024097d4920dc6b5) to address this issue.

## Attack Chain

1.  Attacker identifies a CloudBase-MCP instance running a vulnerable version (<= 2.17.0).
2.  Attacker crafts a malicious HTTP request targeting the `openUrl` API endpoint.
3.  The malicious request includes a `req.body.url` parameter containing a URL pointing to an internal resource (e.g., `http://localhost:8080/admin`) or an external server controlled by the attacker.
4.  The CloudBase-MCP server, without proper validation, processes the request and attempts to open the URL specified in `req.body.url`.
5.  If the URL points to an internal resource, the server retrieves the content of that resource and potentially exposes it to the attacker.
6.  If the URL points to an external server, the server makes an HTTP request to the attacker's server, potentially leaking sensitive information like internal IP addresses or API keys.
7.  The attacker analyzes the response from the server to gather information about the internal network or the CloudBase-MCP instance.
8.  The attacker leverages the gathered information to further compromise the CloudBase-MCP instance or the internal network.

## Impact

Successful exploitation of this SSRF vulnerability can allow attackers to read sensitive information from internal services, bypass firewall restrictions, and potentially gain unauthorized access to internal resources. This could lead to the disclosure of confidential data, compromise of internal systems, and further attacks on the organization's infrastructure. Although the number of victims isn't specified, any unpatched CloudBase-MCP instance is vulnerable.

## Recommendation

*   Upgrade TencentCloudBase CloudBase-MCP to version 2.17.1 or later to apply the patch (3f678a1e7bd400cd76469d61024097d4920dc6b5) that fixes CVE-2026-7221.
*   Implement input validation and sanitization on the `req.body.url` parameter to prevent manipulation by attackers.
*   Monitor web server logs for suspicious requests to the `openUrl` API endpoint with unusual or internal URLs, and deploy the Sigma rules below.
