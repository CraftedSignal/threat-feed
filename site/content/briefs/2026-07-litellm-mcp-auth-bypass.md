---
title: LiteLLM MCP Authentication Bypass via OAuth2 Passthrough Fallback
slug: 2026-07-litellm-mcp-auth-bypass
description: An authentication bypass vulnerability (CVE-2026-59822) exists in LiteLLM's MCP Streamable HTTP endpoint, affecting versions prior to 1.84.0, allowing an unauthenticated attacker to exploit a fallback path that replaces failed key validation with an empty authentication object, leading to the establishment of an authenticated MCP session using arbitrary Bearer tokens, enabling access to configured MCP tools and connected services.
date: "2026-07-22T22:39:57Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:litellm:litellm:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - api-security
  - web-vulnerability
vendors:
  - BerriAI
products:
  - LiteLLM (< 1.84.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Bypass Process Control
    evidence: LiteLLM's MCP Streamable HTTP endpoint could allow an unauthenticated attacker to establish an authenticated MCP session using an arbitrary Bearer token.
    confidence_band: high
cves:
  - id: CVE-2026-59822
    cvss: 8.2
    epss: 0.00243
references:
  - https://github.com/advisories/GHSA-7488-6r32-c95q
  - https://github.com/BerriAI/litellm/releases/tag/v1.84.0
  - CVE-2026-59822
---

A critical authentication bypass vulnerability, tracked as CVE-2026-59822, has been discovered in LiteLLM's MCP (Microservice Communication Protocol) Streamable HTTP endpoint. This flaw, present in versions prior to 1.84.0, allows an unauthenticated attacker to establish an authenticated MCP session by exploiting a specific fallback mechanism in the OAuth2 passthrough handler. When a legitimate LiteLLM key validation fails, the vulnerable system inappropriately replaces the authentication object with an empty one. This behavior permits requests with any fabricated `Authorization: Bearer` token to be processed as authenticated, thereby granting unauthorized access to internal MCP tooling and connected services. The vulnerability puts organizations using LiteLLM at risk of unauthorized data access, command execution via MCP tools, and potential broader system compromise.

## Attack Chain

1. **Reconnaissance**: An attacker identifies publicly exposed LiteLLM instances that utilize the MCP Streamable HTTP endpoint.
2. **Vulnerability Identification**: The attacker determines that the LiteLLM instance is running a version prior to 1.84.0, confirming its susceptibility to CVE-2026-59822.
3. **Craft Malicious Request**: The attacker constructs an HTTP request targeting a sensitive MCP endpoint (e.g., `/mcp/call_tool`, `/mcp/list_tools`) and embeds an arbitrary `Authorization: Bearer <token>` header. The content of the token does not need to be valid or formatted specifically.
4. **Send Request**: The crafted HTTP request is sent to the vulnerable LiteLLM server.
5. **Bypass Authentication**: Upon receiving the request, the LiteLLM server's MCP auth handler attempts key validation. Due to the vulnerability's fallback path, failed validation results in an empty `UserAPIKeyAuth()` object, effectively bypassing the intended authentication check.
6. **Access MCP Tools**: The LiteLLM server processes the request as if it originated from an authenticated user, granting the attacker the ability to list available MCP tools and execute arbitrary calls through them.
7. **Access Connected Services**: Leveraging the compromised MCP session, the attacker interacts with any services connected and exposed via MCP, potentially leading to data exfiltration, system manipulation, or further lateral movement within the network.

## Impact

Successful exploitation of CVE-2026-59822 allows an unauthenticated attacker to gain unauthorized access to LiteLLM's internal MCP tooling and any services integrated with or exposed through it. This can lead to significant data breaches, unauthorized data manipulation, or even remote code execution if the MCP tools provide such capabilities. The number of potentially affected organizations is any LiteLLM user running a vulnerable version with MCP endpoints exposed. While specific victim counts are not available, the nature of the bypass indicates a critical risk for systems handling sensitive data or connected to critical infrastructure through LiteLLM.

## Recommendation

* **Upgrade LiteLLM**: Immediately upgrade all LiteLLM instances to version `1.84.0` or later to patch CVE-2026-59822.
* **Network Segmentation/Blocking**: If immediate upgrading is not feasible, disable MCP routes or block access to `/mcp/` and any related MCP endpoints at your reverse proxy or API gateway.
* **Review Access Logs**: Scrutinize web server or API gateway access logs for unusual requests to `/mcp/` endpoints, especially those with `Authorization: Bearer` headers, as these might indicate attempted exploitation of CVE-2026-59822.
