---
title: Kiota RedirectHandler Leaks Sensitive Headers on Cross-Origin Redirects
slug: 2024-01-09-kiota-redirect-header-leak
description: The RedirectHandler middleware in multiple Kiota libraries fails to strip sensitive HTTP headers (Cookie, Proxy-Authorization, and custom headers) when following 3xx redirects to a different host or scheme, potentially leading to session hijacking, corporate proxy credential theft, and API key theft.
date: "2024-01-09T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - header-injection
  - credential-access
  - cloud
vendors:
  - Microsoft
products:
  - kiota-java
  - KiotaClientFactory.java
  - Kiota
  - Microsoft Graph SDK for Java
  - microsoft-kiota-abstractions
  - Microsoft.Kiota.Abstractions
  - microsoft-kiota-http
  - kiota-typescript
  - kiota-http-go
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-7j59-v9qr-6fq9
rules:
  - title: Detect Cookie Header in Redirect Response
    description: Detects a server response indicating a redirect that includes a Cookie header, which can expose sensitive information.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect Proxy-Authorization Header in Redirect Response
    description: Detects a server response indicating a redirect that includes a Proxy-Authorization header, which can expose proxy credentials.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detecting Suspicious HTTP Headers in Network Traffic
    description: Detects traffic to hosts after a redirect containing Cookie or Proxy-Authorization headers.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - network_connection
      - windows
rules_count: 3
---

The RedirectHandler middleware in Kiota libraries, specifically microsoft-kiota-http-okHttp v1.9.0 for Java, contains a vulnerability where sensitive HTTP headers are not stripped when following 3xx redirects to a different host or scheme. This affects multiple Kiota libraries, including those for .NET, Java, Python, TypeScript, and Go. The vulnerability resides within the `getRedirect` method of the `RedirectHandler` class, where only the Authorization header is removed, while Cookie, Proxy-Authorization, and custom headers are inadvertently forwarded. This is the default middleware used when creating Kiota HTTP clients via `KiotaClientFactory.create()` in Java. Defenders should be aware of potential session hijacking, proxy credential theft, and API key compromise if their applications utilize vulnerable Kiota libraries. The vulnerability was introduced in versions prior to the fixes listed below.

## Attack Chain

1. An attacker identifies a trusted API endpoint that is using a vulnerable Kiota library.
2. The attacker crafts a malicious request to the trusted API endpoint designed to trigger a 3xx redirect. This could be achieved through techniques like open redirect vulnerabilities, man-in-the-middle (MITM) attacks, or DNS rebinding.
3. The trusted API endpoint, upon receiving the malicious request, generates a 302 redirect response, pointing to a malicious attacker-controlled server.
4. The vulnerable Kiota RedirectHandler processes the redirect response, failing to remove the Cookie, Proxy-Authorization, and custom headers from the original request.
5. Kiota constructs a new HTTP request to the attacker-controlled server, including the victim's sensitive headers.
6. The victim's browser or application sends the new request, with the leaked headers, to the attacker's server.
7. The attacker's server captures the sensitive headers, including session cookies, proxy credentials, and API keys.
8. The attacker uses the captured credentials for malicious purposes, such as session hijacking or unauthorized API access.

## Impact

Successful exploitation of this vulnerability can lead to severe consequences, including session hijacking, corporate proxy credential theft, and API key compromise. An attacker capturing session cookies can impersonate a user, gaining unauthorized access to their account and sensitive data. Leaked proxy credentials can allow the attacker to bypass security controls and access internal resources. Exposed API keys grant the attacker the ability to make unauthorized calls to APIs, potentially exfiltrating data or disrupting services. All consumers of kiota-java are affected, including Microsoft Graph SDK for Java.

## Recommendation

*   Upgrade to the latest versions of the affected Kiota libraries to include the patch for CVE-2026-44503.
*   For Java, upgrade `com.microsoft.kiota:microsoft-kiota-abstractions` to version 1.9.1 or later.
*   For .NET, upgrade `Microsoft.Kiota.Abstractions` to version 1.22.0 or later.
*   For Python, upgrade `microsoft-kiota-http` to version 1.9.9 or later.
*   For TypeScript, upgrade `kiota-typescript` to version 1.0.0-preview.100 or later.
*   For Go, upgrade `github.com/microsoft/kiota-http-go` to version 1.5.5 or later.
