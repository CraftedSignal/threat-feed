---
title: Java-SDK DNS Rebinding Vulnerability in MCP Server
slug: 2024-01-java-sdk-dns-rebinding
description: A DNS rebinding vulnerability exists in java-sdk versions prior to 1.0.0, allowing an attacker to access a locally or network-private java-sdk MCP server via a victim's browser, potentially enabling unauthorized tool calls to the server.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - dns-rebinding
  - java-sdk
  - mcp
  - cve-2026-35568
vendors:
  - Model Context Protocol
products:
  - Java SDK
  - MCP Server
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
references:
  - https://github.com/advisories/GHSA-8jxr-pr72-r468
  - https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#security-warning
rules:
  - title: Java-SDK MCP Origin Validation Bypass Attempt
    description: Detects HTTP requests to a Java-SDK MCP server where the Origin header is either missing or does not match the expected Host header, indicating a potential DNS rebinding attack.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Java-SDK MCP Server Tool Call Attempt via HTTP
    description: Detects HTTP requests to a Java-SDK MCP server attempting to execute tool calls.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The java-sdk contains a DNS rebinding vulnerability (CVE-2026-35568) affecting versions prior to 1.0.0. This vulnerability allows a remote attacker to bypass same-origin policy and access a locally or network-private java-sdk MCP (Model Context Protocol) server through a victim's web browser. By exploiting the lack of proper Origin header validation, an attacker can make unauthorized tool calls to the server as if they were a locally running MCP connected AI agent. This issue stems from the MCP server's failure to validate the Origin header on incoming connections, violating the MCP specification's security recommendations. Servers built using frameworks with embedded Origin header validation, such as Spring AI, are not vulnerable.

## Attack Chain

1.  Attacker crafts a malicious website designed to exploit the DNS rebinding vulnerability.
2.  The victim visits the attacker's malicious website in their web browser.
3.  The malicious website contains JavaScript code that attempts to connect to a locally running or private network java-sdk MCP server.
4.  The attacker manipulates DNS records to point the malicious domain to the victim's localhost (127.0.0.1) or a private network IP address where the MCP server is running.
5.  The victim's browser, unaware of the DNS manipulation, sends HTTP requests to the MCP server using the attacker's domain as the origin.
6.  The vulnerable java-sdk MCP server, lacking Origin header validation, accepts the requests as legitimate.
7.  The attacker uses the compromised connection to make arbitrary tool calls to the MCP server.
8.  The MCP server executes the attacker's tool calls, potentially leading to information disclosure, unauthorized actions, or denial of service.

## Impact

Successful exploitation allows attackers to execute arbitrary tool calls on the victim's local or private-network MCP server. This can lead to unauthorized access to sensitive data, manipulation of AI agents connected to the MCP server, or other malicious activities. The impact is significant because it allows bypassing intended security boundaries and gaining unauthorized control over local AI development environments. Any developer who interacts with a malicious website risks inadvertently granting the attacker access to their MCP server.

## Recommendation

*   Deploy the `JavaSDKMCPOriginValidationBypass` Sigma rule to detect potential attempts to exploit this vulnerability by monitoring HTTP requests to MCP servers without proper Origin headers.
*   Implement a reverse proxy (like Nginx or HAProxy) configured to strictly validate the `Host` and `Origin` headers for MCP server traffic, as recommended in the advisory.
*   If possible, migrate to version 1.0.0 or later of the `io.modelcontextprotocol.sdk:mcp-core` package to patch CVE-2026-35568.
*   Consider using frameworks with built-in CORS and Origin validation (such as Spring AI) when building MCP servers.
