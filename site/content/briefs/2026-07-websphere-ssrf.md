---
title: SSRF Vulnerability in IBM WebSphere Application Server
slug: 2026-07-websphere-ssrf
description: IBM WebSphere Application Server and Liberty are vulnerable to unauthenticated Server-Side Request Forgery (SSRF) when the SIP container feature is enabled, allowing attackers to perform unauthorized requests to internal services.
date: "2026-07-29T19:17:55Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - ssrf
  - webserver
  - vulnerability
vendors:
  - IBM
products:
  - WebSphere Application Server (9.0)
  - WebSphere Application Server (8.5)
  - WebSphere Application Server - Liberty (17.0.0.3 - 26.0.0.8)
cves:
  - id: CVE-2026-14529
    cvss: 9.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14529
  - https://www.ibm.com/support/pages/node/7281721
---

IBM has disclosed a critical Server-Side Request Forgery (SSRF) vulnerability, tracked as CVE-2026-14529, affecting IBM WebSphere Application Server 9.0 and 8.5, and WebSphere Application Server - Liberty versions 17.0.0.3 through 26.0.0.8. The vulnerability manifests when the Session Initiation Protocol (SIP) container feature (sipServlet-1.1) is enabled. An unauthenticated attacker can exploit this flaw to induce the server to make arbitrary HTTP requests, potentially resulting in unauthorized access to sensitive internal network resources, service disruption, or information disclosure. Given the critical CVSS 3.1 score of 9.4 and the potential for unauthenticated exploitation, immediate attention is required to audit SIP configuration and apply vendor-supplied patches.

## Attack Chain

1. Attacker performs reconnaissance to identify exposed WebSphere instances with the sipServlet-1.1 feature enabled.
2. Attacker crafts a malicious HTTP request targeting the SIP container interface of the application server.
3. Attacker injects a target URL into the request parameters intended for the SIP servlet.
4. The vulnerable WebSphere Application Server fails to validate the requested destination URL.
5. The server acts as a proxy, executing an outbound request on behalf of the attacker to an internal network resource or service.
6. Internal services, which may trust the application server's origin, process the request and return sensitive data or perform administrative actions.
7. Attacker receives the response or confirms the impact of the request via the intercepted application flow.

## Impact

Successful exploitation of CVE-2026-14529 allows for unauthenticated access to internal network infrastructure that is otherwise protected by perimeter firewalls. This can lead to the exposure of proprietary internal data, unauthorized interaction with internal APIs, or service degradation. The vulnerability affects a broad range of enterprise-grade application server versions, making it a high-value target for attackers looking to pivot from a public-facing web presence into a secure internal network.

## Recommendation

* Prioritize patching IBM WebSphere Application Server and Liberty to the latest version provided in the IBM security bulletin (https://www.ibm.com/support/pages/node/7281721).
* Disable the SIP container feature (sipServlet-1.1) if it is not strictly required for business operations.
* Implement strict egress filtering on the application server to prevent connections to sensitive internal subnets or unauthorized external endpoints.
* Monitor web server access logs for anomalous requests to SIP-related endpoints that contain suspicious or internal URLs in query parameters.
