---
title: n8n-mcp Multi-Tenant Credential Fallback Vulnerability
slug: 2026-05-n8n-mcp-tenant-fallback
description: When ENABLE_MULTI_TENANT=true, n8n-mcp requests that omit x-n8n-url or x-n8n-key headers silently fall back to the process-level N8N_API_URL / N8N_API_KEY credentials configured for the operator's own n8n instance; an authenticated MCP tenant could cause n8n management calls to execute against the operator's instance instead of its own, leading to potential data access and code execution on the operator's n8n instance.
date: "2026-05-18T17:42:22Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - privilege-escalation
  - cve-2026-45707
vendors:
  - n8n
products:
  - n8n-mcp (<= 2.51.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-jxx9-px88-pj69
rules:
  - title: Detect n8n-mcp Multi-Tenant API Key Fallback Attempt - Missing Headers
    description: Detects attempts to exploit the n8n-mcp multi-tenant credential fallback vulnerability (CVE-2026-45707) by identifying HTTP requests lacking the required x-n8n-url and x-n8n-key headers.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555.004
    data_sources:
      - webserver
  - title: Detect n8n-mcp Operator API Key Usage from Non-Operator IP
    description: Detects potential exploitation of CVE-2026-45707 by flagging API requests using the operator's N8N_API_KEY originating from an unexpected IP address (i.e., not the operator's usual IP).
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1555.004
    data_sources:
      - webserver
rules_count: 2
---

The n8n-mcp is vulnerable to a credential fallback issue when running in multi-tenant mode (ENABLE_MULTI_TENANT=true). Specifically, when HTTP requests to the n8n-mcp instance lack the required `x-n8n-url` and/or `x-n8n-key` headers, the application unexpectedly defaults to using the operator's own n8n instance credentials (N8N_API_URL / N8N_API_KEY). This design flaw allows an authenticated tenant on the MCP platform to inadvertently, or maliciously, execute n8n management calls against the operator's environment instead of their own isolated instance. This vulnerability affects HTTP-mode deployments of `n8n-mcp` versions 2.51.1 and earlier that are configured as a shared multi-tenant service.

## Attack Chain

1. An attacker gains access to an n8n-mcp tenant account within a multi-tenant deployment where `ENABLE_MULTI_TENANT=true`.
2. The attacker crafts an HTTP request intended for their own n8n instance, but intentionally omits the `x-n8n-url` and/or `x-n8n-key` headers.
3. The n8n-mcp instance, upon receiving the incomplete request, fails to properly validate the tenant context due to the missing headers.
4. Instead of rejecting the request, the n8n-mcp instance incorrectly falls back to using the operator's configured `N8N_API_URL` and `N8N_API_KEY`.
5. The attacker's request is then processed, leveraging the operator's credentials to interact with the operator's n8n instance.
6. Depending on the permissions associated with the operator's API key, the attacker could potentially read or modify workflows, credentials, executions, and data tables within the operator's n8n environment.
7. If the operator's n8n instance has Code nodes enabled and sufficient permissions, the attacker could potentially escalate to remote code execution within the operator's n8n runtime environment by manipulating workflows.
8. The final objective is unauthorized access to the operator's n8n instance, potentially leading to data breaches, service disruption, or further lateral movement within the operator's infrastructure.

## Impact

Successful exploitation of this vulnerability (CVE-2026-45707) allows a malicious tenant to read and write workflows, executions, data-table contents, and credential metadata on the operator's n8n instance. If the operator's n8n permits Code-node execution that reaches OS-level modules, the path could escalate to remote code execution inside the operator's n8n runtime. This could result in a complete compromise of the operator's n8n instance and its associated data, with potential impact on the operator's business operations and sensitive information.

## Recommendation

- Upgrade to n8n-mcp version 2.51.2 or later to remediate CVE-2026-45707.
- If immediate patching is not possible, set `ENABLE_MULTI_TENANT=false` to disable multi-tenant mode, effectively isolating each tenant's n8n instance.
- Implement a proxy or web application firewall (WAF) rule to reject requests missing both the `x-n8n-url` and `x-n8n-key` headers to mitigate the primary attack vector.
- Review and restrict the scopes of the operator's `N8N_API_KEY` to the minimum required permissions to limit the blast radius in case of a successful fallback.
