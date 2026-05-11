---
title: Next.js Cache Components Vulnerable to Denial-of-Service via Connection Exhaustion (CVE-2026-44579)
slug: 2026-05-nextjs-dos
description: Next.js applications using Partial Prerendering through Cache Components are vulnerable to connection exhaustion (CVE-2026-44579), where crafted POST requests to a server action trigger a request-body handling deadlock, consuming server capacity and leading to denial of service.
date: "2026-05-11T15:59:02Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - connection-exhaustion
  - next.js
  - cve-2026-44579
vendors:
  - npm
products:
  - next (< 15.5.16)
  - next (< 16.2.5)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-mg66-mrh9-m8jx
  - CVE-2026-44579
rules:
  - title: Detect Suspicious Next-Resume Header
    description: Detects HTTP requests containing the Next-Resume header, which is now considered internal-only in Next.js versions >=15.5.16 and >=16.2.5 and should not be present in external requests, indicating a potential CVE-2026-44579 exploitation attempt.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499
    data_sources:
      - webserver
  - title: Detect High Volume of POST Requests to Server Action Endpoints
    description: Detects a high volume of POST requests to common server action endpoints, which could indicate a denial-of-service attack targeting specific Next.js functionalities.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499
    data_sources:
      - webserver
rules_count: 2
---

A denial-of-service vulnerability (CVE-2026-44579) exists in Next.js applications that utilize Partial Prerendering through the Cache Components feature. This flaw allows an attacker to exhaust server connections by sending specially crafted POST requests to a server action. The malicious requests trigger a deadlock in request-body handling, causing connections to remain open for an extended period. This leads to the consumption of file descriptors and server capacity, ultimately denying service to legitimate users. The vulnerability affects Next.js versions 15.0.0 up to 15.5.16 and 16.0.0 up to 16.2.5. The fix implemented involves treating the `Next-Resume` header as internal-only and stripping it from untrusted incoming requests to prevent external manipulation.

## Attack Chain

1. The attacker identifies a Next.js application using Partial Prerendering and Cache Components.
2. The attacker crafts a malicious POST request targeted at a server action endpoint.
3. The malicious POST request includes a `Next-Resume` header, intended to exploit the partial prerendering mechanism.
4. The Next.js application, upon receiving the crafted request, enters a deadlock state while processing the request body.
5. The connection remains open and consumes server resources, including file descriptors.
6. The attacker sends multiple such malicious POST requests concurrently, amplifying the resource consumption.
7. The server's capacity to handle new connections diminishes due to the exhausted resources.
8. Legitimate users are denied service as the server is unable to accept new connections or process their requests, resulting in a denial-of-service condition.

## Impact

Successful exploitation of CVE-2026-44579 leads to a denial-of-service condition, rendering Next.js applications unavailable to legitimate users. The number of victims is directly proportional to the attacker's ability to send concurrent malicious requests and the server's capacity to handle connections. Sectors reliant on Next.js applications for critical services, such as e-commerce, content delivery, and web applications, are particularly vulnerable. The vulnerability can severely impact business operations, causing financial losses, reputational damage, and disruption of services.

## Recommendation

*   Upgrade Next.js to version 15.5.16 or later for the 15.x branch, or version 16.2.5 or later for the 16.x branch, to incorporate the fix for CVE-2026-44579.
*   As a temporary workaround, block incoming requests containing the `Next-Resume` header at the edge to prevent exploitation until the upgrade can be performed (see Overview).
*   Deploy the Sigma rule `Detect Suspicious Next-Resume Header` to identify potential exploitation attempts by monitoring for the presence of the `Next-Resume` header in incoming HTTP requests.
*   Monitor web server access logs for a high volume of POST requests to server action endpoints, which could indicate an attempted denial-of-service attack, and correlate with the `Next-Resume` header to refine detection.
