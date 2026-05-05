---
title: Open-WebSearch SSRF Vulnerability in fetchWebContent Tool
slug: 2024-01-open-websearch-ssrf
description: Open-WebSearch has a Server-Side Request Forgery (SSRF) vulnerability in the `fetchWebContent` MCP tool due to improper validation of IPv6 literals and lack of DNS resolution, allowing attackers to fetch arbitrary private-network URLs and receive the response body.
date: "2026-05-05T20:51:45Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - ssrf
  - open-websearch
  - vulnerability
vendors:
  - Aas-ee
products:
  - open-webSearch
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Server-Side Request Forgery
references:
  - https://github.com/advisories/GHSA-v228-72c7-fx8j
iocs:
  - type: url
    value: http://127.0.0.1:3000/mcp
ioc_counts:
  url: 1
rules:
  - title: Detect Open-WebSearch SSRF via IPv6 Bypass
    description: Detects SSRF attempts in Open-WebSearch by identifying requests with bracketed IPv6 literals.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1199
    data_sources:
      - webserver
      - linux
  - title: Detect Open-WebSearch fetchWebContent Tool Execution
    description: Detects execution of the fetchWebContent tool in Open-WebSearch, which is the entrypoint for SSRF.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1199
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Open-WebSearch is vulnerable to a Server-Side Request Forgery (SSRF) in the `fetchWebContent` tool. This vulnerability stems from two primary defects in the `isPublicHttpUrl` function within `src/utils/urlSafety.ts`. First, the function fails to recognize bracketed IPv6 literals, like `[::1]`, allowing them to bypass the private network checks. Second, the function lacks DNS resolution for hostnames, meaning that any attacker-controlled hostname resolving to a private IP address (e.g., 127.0.0.1) will pass the validation. Successful exploitation allows an attacker to make the server fetch content from internal resources. The vulnerability exists in version HEAD as of 2026-05-05. Because the tool returns the response body to the MCP caller, the SSRF is non-blind. The vulnerability is exploitable over stdio and is pre-auth when `enableHttpServer` is set.

## Attack Chain

1.  An attacker sends a POST request to the `/mcp` endpoint to initialize an MCP session, obtaining an `mcp-session-id`.
2.  The attacker sends another POST request to `/mcp` with the `notifications/initialized` method and the obtained `mcp-session-id`.
3.  The attacker crafts a malicious POST request to `/mcp` with the `tools/call` method to invoke the `fetchWebContent` tool.
4.  The malicious request includes a URL containing a bracketed IPv6 literal (e.g., `http://[::ffff:7f00:1]:19999/internal`) or an attacker-controlled hostname resolving to a private IP address as the target.
5.  The `isPublicHttpUrl` function fails to properly validate the URL due to the defects in IPv6 literal recognition and lack of DNS resolution.
6.  The `fetchWebContent` tool uses `axios.get` to fetch content from the attacker-specified URL.
7.  The response from the internal resource is retrieved and formatted as JSON.
8.  The `fetchWebContent` tool returns the content to the attacker.

## Impact

This SSRF vulnerability allows an attacker to make the Open-WebSearch server fetch content from arbitrary private-network URLs. This includes AWS EC2 metadata endpoints, internal dashboards, services running on loopback, and RFC1918 neighbors. The vulnerability is pre-authentication when the `enableHttpServer` configuration is enabled, potentially leading to full system compromise or data exfiltration from internal services. Furthermore, the CORS `*` configuration on `/mcp` allows for DNS rebinding attacks.

## Recommendation

*   Deploy the `DetectOpenWebSearchSSRFIPv6` Sigma rule to detect attempts to exploit the IPv6 bypass vulnerability.
*   Deploy the `DetectOpenWebSearchfetchWebContent` Sigma rule to detect usage of the vulnerable fetchWebContent tool.
*   Restrict access to the `/mcp` endpoint by implementing authentication and access controls to prevent unauthorized tool execution, as mentioned in the overview.
*   Monitor network connections originating from the Open-WebSearch server to identify any unexpected or unauthorized connections to internal resources.
