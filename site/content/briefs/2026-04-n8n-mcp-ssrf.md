---
title: n8n-mcp SDK Embedder SSRF Vulnerability via IPv6 Bypass
slug: 2026-04-n8n-mcp-ssrf
description: The n8n-mcp SDK embedder path is vulnerable to server-side request forgery (SSRF) due to the synchronous URL validator in `SSRFProtection.validateUrlSync()` not checking for IPv6 addresses, allowing attackers to access cloud metadata endpoints, RFC1918 private networks, or localhost services by supplying a crafted `n8nApiUrl`.
date: "2026-04-30T18:12:54Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - cwe-918
  - n8n-mcp
vendors:
  - n8n
products:
  - n8n-mcp (>= 2.47.4, < 2.47.14)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-56c3-vfp2-5qqj
rules:
  - title: Detect N8N MCP SSRF Attempt via IPv6 Bypass
    description: Detects potential SSRF attempts in N8N MCP by monitoring network connections to internal IP ranges using IPv6 mapped IPv4 addresses.
    platform: sigma
    severity: high
    tactics:
      - impact
      - initial_access
    techniques:
      - T1190
      - T1595
    data_sources:
      - network_connection
      - linux
  - title: Detect N8N MCP SSRF Attempt via IPv6 Cloud Metadata
    description: Detects potential SSRF attempts in N8N MCP by monitoring network connections to Cloud Metadata IPs using IPv6 mapped IPv4 addresses.
    platform: sigma
    severity: high
    tactics:
      - impact
      - initial_access
    techniques:
      - T1190
      - T1595
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

The n8n-mcp library, when embedded as an SDK, contains a server-side request forgery (SSRF) vulnerability. The vulnerability lies in the `SSRFProtection.validateUrlSync()` function, specifically within the `N8NDocumentationMCPServer` constructor, `getN8nApiClient()`, and `validateInstanceContext()` methods. This synchronous validator lacks IPv6 checks, allowing IPv4-mapped IPv6 addresses (e.g., `http://[::ffff:169.254.169.254]`) to bypass existing protections against cloud metadata, localhost, and private IP ranges. An attacker who can control the `n8nApiUrl` parameter can exploit this flaw to force the server to make HTTP requests to internal or external services. This issue affects deployments embedding n8n-mcp as an SDK using `N8NDocumentationMCPServer` or `N8NMCPEngine` with user-supplied `InstanceContext` on versions v2.47.4 through v2.47.13. Version v2.47.14 and later contain the patch for this vulnerability.

## Attack Chain

1. An attacker identifies a vulnerable n8n-mcp deployment embedding the SDK and using a user-supplied `InstanceContext`.
2. The attacker crafts a malicious `n8nApiUrl` containing an IPv4-mapped IPv6 address, such as `http://[::ffff:169.254.169.254]`.
3. The attacker supplies the crafted `n8nApiUrl` to the vulnerable `N8NDocumentationMCPServer` constructor or `getN8nApiClient()` method.
4. The `validateInstanceContext()` function calls `SSRFProtection.validateUrlSync()` to validate the URL.
5. The `validateUrlSync()` function fails to properly validate the IPv4-mapped IPv6 address.
6. The server issues an HTTP request to the attacker-specified target using the bypassed URL.
7. The `x-n8n-api-key` header is forwarded to the attacker-controlled target.
8. The response body from the target is returned to the attacker, allowing the attacker to gather sensitive information from internal services or cloud metadata endpoints.

## Impact

Successful exploitation of this SSRF vulnerability allows an attacker to perform unauthorized actions, such as accessing sensitive information from cloud metadata endpoints (AWS IMDS, GCP, Azure, Alibaba, Oracle), RFC1918 private networks, or localhost services. The attacker can also gain access to the `n8nApiKey`, which is forwarded in the `x-n8n-api-key` header, potentially leading to further compromise of the n8n instance. This vulnerability impacts deployments embedding n8n-mcp as an SDK between versions v2.47.4 and v2.47.13.

## Recommendation

*   Upgrade n8n-mcp to version v2.47.14 or later to patch the vulnerability as described in the advisory.
*   Implement a network-level block on outbound traffic from the n8n-mcp process to RFC1918 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), link-local `169.254.0.0/16`, and cloud metadata endpoints as a defense-in-depth measure.
*   Deploy the Sigma rule `Detect N8N MCP SSRF Attempt via IPv6 Bypass` to identify exploitation attempts by detecting outbound connections to internal IPs using IPv6 mapped IPv4 address.
