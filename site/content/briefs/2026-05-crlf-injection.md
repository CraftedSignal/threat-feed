---
title: CVE-2026-1502 HTTP Client Proxy Tunnel Headers CR/LF Injection Vulnerability
slug: 2026-05-crlf-injection
description: CVE-2026-1502 is a critical vulnerability in Microsoft HTTP client proxy tunnel header validation, potentially allowing for CR/LF injection attacks.
date: "2026-05-26T07:36:41Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - crlf-injection
  - http-request-smuggling
  - proxy-vulnerability
  - cve
vendors:
  - Microsoft
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-1502
    epss: 0.00024
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-1502
rules:
  - title: Detect Suspicious CR/LF Injection in HTTP Proxy Tunnel Headers
    description: Detects CVE-2026-1502 exploitation — attempts to inject CR/LF characters into HTTP proxy tunnel headers, potentially leading to HTTP request smuggling.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - proxy
  - title: Detect Suspicious CR/LF Injection in HTTP Proxy Tunnel Headers (URL Encoded)
    description: Detects CVE-2026-1502 exploitation — URL-encoded CR/LF characters in the Host header during a CONNECT request may indicate an attempt to exploit CR/LF injection vulnerabilities.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - proxy
rules_count: 2
---

CVE-2026-1502 is a security vulnerability affecting Microsoft products due to insufficient validation of HTTP client proxy tunnel headers. This lack of validation allows for the potential injection of Carriage Return (CR) and Line Feed (LF) characters, which could lead to various attacks, including HTTP request smuggling and other forms of server-side injection. While specific product versions are not detailed in the initial advisory, the vulnerability's nature suggests broad applicability across Microsoft's HTTP client implementations. Successful exploitation could allow attackers to manipulate server responses, potentially leading to information disclosure, session hijacking, or other malicious activities. Defenders should prioritize patching and implementing detection measures to mitigate this risk.

## Attack Chain

1. An attacker crafts a malicious HTTP request containing a proxy tunnel header with embedded CR/LF characters.
2. The vulnerable Microsoft HTTP client processes the request and forwards it to the specified proxy server without properly sanitizing the headers.
3. The proxy server interprets the injected CR/LF sequences as the end of the header section, potentially allowing the attacker to inject arbitrary HTTP headers or even a complete HTTP request.
4. If the attacker injects new headers, they could modify the request's behavior, such as setting a different Host header or injecting authentication credentials.
5. If the attacker injects a complete HTTP request, they can perform HTTP request smuggling, where the proxy server processes the malicious request alongside legitimate requests.
6. The smuggled request can target different resources or even internal services that are not directly accessible from the internet.
7. The server processes the smuggled request, potentially executing arbitrary code or disclosing sensitive information.
8. The attacker gains unauthorized access to the system or sensitive data.

## Impact

Successful exploitation of CVE-2026-1502 could lead to severe consequences, including unauthorized access to sensitive data, session hijacking, and even remote code execution. Due to the nature of HTTP request smuggling, the impact could extend beyond the initially targeted application, potentially affecting other services sharing the same infrastructure. The number of potential victims is substantial, given the widespread use of Microsoft's HTTP client implementations.

## Recommendation

*   Apply the security update released by Microsoft to address CVE-2026-1502 as soon as possible (reference: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-1502).
*   Deploy the Sigma rule "Detect Suspicious CR/LF Injection in HTTP Proxy Tunnel Headers" to identify potential exploitation attempts targeting CVE-2026-1502.
*   Enable detailed logging for HTTP proxy traffic to facilitate investigation of potential attacks related to CVE-2026-1502.
