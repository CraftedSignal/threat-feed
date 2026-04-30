---
title: cpp-httplib Vulnerability Leads to Credential Leakage via HTTP Redirects
slug: 2026-03-cpp-httplib-credential-leak
description: The cpp-httplib library prior to version 0.39.0 forwards stored authentication credentials to arbitrary hosts via HTTP redirects, potentially exposing sensitive information to malicious actors.
date: "2026-03-27T01:16:21Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cpp-httplib
  - credential-leak
  - cve-2026-33745
  - http-redirect
  - credential-access
  - cross-origin
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33745
rules:
  - title: Detect Outbound HTTP Request with Authorization Header to Unfamiliar Domain
    description: Detects an outbound HTTP request containing an Authorization header to a domain not in a whitelist, which could indicate credential theft via HTTP redirect vulnerability (CVE-2026-33745).
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - network_connection
      - windows
  - title: Detect Process Making Network Connections with Authorization Header Set
    description: Detects a process making network connections where the authorization header is being sent. Requires process creation and network connection logs.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The cpp-httplib library, a C++11 single-file header-only cross platform HTTP/HTTPS library, contains a vulnerability (CVE-2026-33745) in versions prior to 0.39.0. This flaw allows an attacker to potentially steal sensitive credentials by exploiting the library's behavior when handling cross-origin HTTP redirects (301, 302, 307, 308). Specifically, stored Basic Auth, Bearer Token, and Digest Auth credentials are unintentionally forwarded to arbitrary hosts during these redirects. This means a compromised server or a malicious actor can redirect a client using the vulnerable library to a host under their control, effectively capturing the plaintext credentials within the `Authorization` header. Upgrading to version 0.39.0 resolves this vulnerability. This is critical because it impacts any application using the vulnerable version of the library and relying on HTTP authentication.

## Attack Chain

1.  Attacker compromises or sets up a malicious HTTP server.
2.  Attacker crafts a response that includes an HTTP redirect (301, 302, 307, or 308) to a domain controlled by the attacker. This redirect targets a resource on the attacker's controlled domain.
3.  A client application using a vulnerable version of cpp-httplib (prior to 0.39.0) attempts to access a resource on the compromised or malicious server.
4.  The cpp-httplib library in the client application receives the HTTP redirect response.
5.  The vulnerable library incorrectly appends any stored `Authorization` headers (Basic Auth, Bearer Token, or Digest Auth) to the redirected request, even though it's a cross-origin request.
6.  The client application, through cpp-httplib, sends the redirected request to the attacker-controlled host, including the sensitive `Authorization` header.
7.  The attacker captures the `Authorization` header, extracting the plaintext credentials.
8.  The attacker uses the stolen credentials to impersonate the user or gain unauthorized access to protected resources.

## Impact

Successful exploitation of CVE-2026-33745 allows attackers to steal authentication credentials from applications utilizing the vulnerable cpp-httplib library. The impact could range from unauthorized access to user accounts and sensitive data to full compromise of the application and its related systems. The number of potential victims depends on the usage and distribution of the vulnerable cpp-httplib library across different software projects and organizations. Organizations across all sectors are potentially vulnerable if they use affected applications.

## Recommendation

*   Upgrade to cpp-httplib version 0.39.0 or later to remediate CVE-2026-33745 as mentioned in the **Overview**.
*   Implement network monitoring to detect HTTP requests containing `Authorization` headers being sent to unexpected or untrusted domains, based on the attack chain steps described above, specifically step 6.
*   If upgrading is not immediately feasible, consider implementing a proxy that strips `Authorization` headers from HTTP redirect requests to external domains as a temporary mitigation.
