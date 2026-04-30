---
title: JoeCastrom mcp-chat-studio Server-Side Request Forgery Vulnerability
slug: 2024-01-mcp-chat-studio-ssrf
description: A server-side request forgery vulnerability exists in JoeCastrom mcp-chat-studio up to version 1.5.0 in the LLM Models API component, allowing remote attackers to manipulate the req.query.base_url argument and potentially conduct further attacks.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-7147
  - ssrf
  - mcp-chat-studio
vendors:
  - JoeCastrom
products:
  - mcp-chat-studio
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
cves:
  - id: CVE-2026-7147
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7147
rules:
  - title: Detect mcp-chat-studio SSRF Attempt via Base URL Manipulation
    description: Detects potential SSRF attempts in mcp-chat-studio by monitoring requests to /routes/llm.js with suspicious URLs in the base_url parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect mcp-chat-studio SSRF Attempt to Internal IPs
    description: Detects potential SSRF attempts in mcp-chat-studio by monitoring requests to /routes/llm.js with internal IPs in the base_url parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A server-side request forgery (SSRF) vulnerability has been identified in JoeCastrom's mcp-chat-studio, affecting versions up to 1.5.0. The vulnerability resides within the LLM Models API, specifically in the `server/routes/llm.js` file. An attacker can remotely exploit this flaw by manipulating the `req.query.base_url` argument. This allows the attacker to make arbitrary HTTP requests from the server, potentially leading to information disclosure, internal service access, or other malicious activities. The vulnerability is publicly known and actively discussed, increasing the risk of exploitation. The vendor was notified but has not yet responded.

## Attack Chain

1.  The attacker identifies an mcp-chat-studio instance running a vulnerable version (<= 1.5.0).
2.  The attacker crafts a malicious HTTP request targeting the `/routes/llm.js` endpoint.
3.  Within the request, the attacker manipulates the `req.query.base_url` parameter to point to an attacker-controlled server or an internal resource.
4.  The mcp-chat-studio server processes the request and, due to the SSRF vulnerability, makes an HTTP request to the URL specified in the `req.query.base_url` parameter.
5.  If the attacker controls the `base_url`, they can intercept the request and potentially steal sensitive information.
6.  If the `base_url` points to an internal resource, the attacker may gain unauthorized access to internal services or data.
7.  The attacker analyzes the response from the manipulated request to gather information about the internal network or services.
8.  The attacker leverages the gained information to further compromise the mcp-chat-studio instance or the internal network.

## Impact

Successful exploitation of this SSRF vulnerability can allow an attacker to read sensitive data from internal services, potentially leading to credential theft or data exfiltration. It can also be used to pivot to other internal systems, causing a wider breach. The lack of vendor response increases the risk, as no patch or mitigation is currently available. The CVSS v3.1 base score is 7.3, indicating a high severity vulnerability.

## Recommendation

*   Monitor web server logs for requests to `/routes/llm.js` containing suspicious URLs in the `req.query.base_url` parameter using the provided Sigma rule.
*   Implement network segmentation to limit the impact of potential SSRF attacks by restricting access from the mcp-chat-studio server to internal resources.
*   Since no patch is available, consider applying a web application firewall (WAF) rule to filter requests to `/routes/llm.js` that contain potentially malicious URLs in the `req.query.base_url` parameter.
