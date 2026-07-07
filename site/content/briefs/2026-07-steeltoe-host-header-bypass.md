---
title: Steeltoe Host Header Bypass Vulnerability (CVE-2026-50194)
slug: 2026-07-steeltoe-host-header-bypass
description: An unauthenticated remote attacker can bypass port isolation in Steeltoe applications configured with `Management:Endpoints:Port` by spoofing the Host HTTP header, allowing access to all actuator endpoints (CVE-2026-50194).
date: "2026-07-03T11:24:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - web-exploitation
  - cve
  - dotnet
  - bypass
vendors:
  - Steeltoe
products:
  - Steeltoe.Management.Endpoint <= 4.1.0
  - Steeltoe.Management.EndpointCore >= 3.2.2, <= 3.3.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated remote attacker can reach every actuator endpoint using a specially crafted HTTP request.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: When Steeltoe management endpoints are configured to listen on an alternate port... the middleware responsible for restricting access to the endpoints uses the `Host` HTTP header rather than the actual network socket port.
    confidence_band: high
cves:
  - id: CVE-2026-50194
    cvss: 8.2
    epss: 0.00238
references:
  - https://github.com/advisories/GHSA-58f6-6rj2-3v8r
rules:
  - title: Detect CVE-2026-50194 Exploitation - Steeltoe Host Header Bypass
    description: Detects attempts to exploit CVE-2026-50194 by sending requests to Steeltoe actuator endpoints where the `Host` header specifies a non-standard port, indicating an attempt to bypass port isolation.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A critical vulnerability (CVE-2026-50194) in Steeltoe applications allows unauthenticated remote attackers to bypass port isolation for management endpoints. This flaw affects configurations where `Management:Endpoints:Port` is explicitly set to a port different from the application's primary listener. The middleware, intended to restrict access, incorrectly relies on the `Host` HTTP header rather than the actual network socket port. By crafting a request with a spoofed `Host` header specifying the management port, attackers can trick the application into granting access to all actuator endpoints. This enables unauthorized control, information disclosure, and potential configuration manipulation, making it a high-severity concern for organizations using vulnerable Steeltoe versions, specifically `Steeltoe.Management.Endpoint` up to 4.1.0 and `Steeltoe.Management.EndpointCore` versions between 3.2.2 and 3.3.0.

## Attack Chain

1.  Attacker identifies a publicly accessible Steeltoe application that is likely using management endpoints.
2.  The target Steeltoe application is configured with `Management:Endpoints:Port` set to a port different from its main listener (e.g., application on 80/443, management on 8080).
3.  Attacker crafts an HTTP request targeting the application's main listener port, typically 80 or 443.
4.  The crafted request includes a spoofed `Host` HTTP header, setting its value to the application's domain combined with the configured `Management:Endpoints:Port` (e.g., `Host: example.com:8080`).
5.  The request scheme (HTTP/HTTPS) matches the `Management:Endpoints:SslEnabled` setting of the application.
6.  The Steeltoe middleware, upon receiving the request, evaluates the `Host` header for port isolation rather than the actual socket port the request arrived on.
7.  The spoofed `Host` header causes the middleware to erroneously permit access as if the request originated on the designated management port.
8.  Attacker gains unauthenticated access to all management actuator endpoints (e.g., `/actuator/health`, `/actuator/env`), enabling information disclosure or potential configuration changes.

## Impact

The successful exploitation of CVE-2026-50194 grants unauthenticated remote attackers full access to Steeltoe's management actuator endpoints. This can lead to severe consequences, including sensitive information disclosure (e.g., environment variables, application configuration), arbitrary configuration modifications, and potentially remote code execution if certain actuators are exposed and misconfigured. While no specific victim count has been reported, any organization deploying Steeltoe applications with the described vulnerable configuration is at risk. The ease of exploitation via a simple HTTP header manipulation makes this a high-risk vulnerability for data exposure and unauthorized system control.

## Recommendation

*   Immediately upgrade `Steeltoe.Management.Endpoint` to version 4.1.1 or higher, and `Steeltoe.Management.EndpointCore` to version 3.3.1 or higher, to address CVE-2026-50194.
*   Deploy the provided Sigma rule to your SIEM, tuning `cs-host` to match your expected application domain and monitoring for `cs-uri-stem` containing `/actuator/` with unexpected port values in the `Host` header.
*   Implement explicit ASP.NET Core authorization (`RequireAuthorization`) on all sensitive actuator endpoints as a defense-in-depth measure, as recommended by the Steeltoe advisory.
*   Configure reverse proxies or load balancers in front of Steeltoe applications to strictly enforce expected `Host` header values, preventing clients from specifying arbitrary ports.
