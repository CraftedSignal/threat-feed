---
title: Spring AI MCP Security Unvalidated URL Fetching (SSRF)
slug: 2026-05-spring-ai-ssrf
description: The mcp-security framework fails to implement SSRF mitigations outlined in the Model Context Protocol, processing untrusted URLs for OAuth-related discovery and metadata without verification, affecting installations with Dynamic Client Registration (DCR) enabled and exposing them to potential Server-Side Request Forgery (SSRF) attacks, tracked as CVE-2026-45609.
date: "2026-05-18T13:30:43Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - spring-ai
  - oauth
  - cve-2026-45609
vendors:
  - Spring AI Community
products:
  - mcp-client-security (< 0.1.9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-qjp4-4jvr-xqg3
  - https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices#mitigation-3
rules:
  - title: Detect Spring AI MCP SSRF via DCR
    description: Detects CVE-2026-45609 exploitation -- Outbound connection initiated from Spring AI MCP application during Dynamic Client Registration to suspicious or internal IPs/domains
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
  - title: Detect Spring AI MCP Suspicious DCR URL
    description: Detects CVE-2026-45609 exploitation -- Detects connections to suspicious URLs during Spring AI MCP DCR (Dynamic Client Registration).
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

The mcp-security framework, specifically versions prior to 0.1.9, does not enforce mandatory SSRF mitigations as outlined in the Model Context Protocol (MCP) security specifications. This vulnerability, tracked as CVE-2026-45609, stems from the framework's processing of untrusted URLs for OAuth-related discovery and metadata without proper validation. The issue arises when Dynamic Client Registration (DCR) is enabled, as it fails to validate URLs exposed by MCP Servers (protected resource metadata URL, authorization server URL) and Authorization Servers (all OAuth2 endpoints). This lack of validation allows attackers to potentially manipulate the application into making requests to internal or malicious external servers.

## Attack Chain

1. An attacker identifies a Spring AI MCP application with Dynamic Client Registration (DCR) enabled.
2. The attacker crafts a malicious URL pointing to an internal service or external server.
3. The attacker provides this malicious URL as part of the DCR process, potentially as the protected resource metadata URL, authorization server URL, or OAuth2 endpoint.
4. The application, without proper validation, attempts to fetch metadata or interact with the server specified in the malicious URL.
5. If the URL points to an internal service, the attacker can potentially gain access to sensitive internal resources or configurations.
6. If the URL points to an external server, the attacker can potentially exfiltrate sensitive data or perform other malicious actions.
7. The vulnerable application inadvertently makes a request to the attacker-controlled resource.
8. The attacker monitors access logs on the controlled resource, gathers sensitive data and continues pivoting within the environment.

## Impact

Successful exploitation of this SSRF vulnerability (CVE-2026-45609) could allow an attacker to access internal resources, exfiltrate sensitive data, or perform other malicious actions within the network. While the exact number of affected installations is unknown, any Spring AI MCP application with DCR enabled is potentially vulnerable. This could lead to data breaches, service disruptions, or further compromise of the application and its environment.

## Recommendation

*   Upgrade to version 0.1.9 or later of `org.springaicommunity:mcp-client-security` to patch CVE-2026-45609.
*   If upgrading is not immediately feasible, implement the workaround suggested by Spring AI Community by providing a custom `McpOAuth2ClientManager` that includes URL filtering.
*   Apply URL filtering through `ClientHttpRequestInterceptor` within the `RestClient` used by `McpMetadataDiscoveryService` and `DynamicClientRegistrationService` to prevent unauthorized URL access.
*   Deploy the Sigma rule "Detect Spring AI MCP SSRF via DCR" to identify potential exploitation attempts.
