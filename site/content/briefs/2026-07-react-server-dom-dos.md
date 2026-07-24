---
title: Denial of Service Vulnerability in React Server Components
slug: 2026-07-react-server-dom-dos
description: A denial of service vulnerability (CVE-2026-44907) affects multiple versions of the react-server-dom-webpack, react-server-dom-parcel, and react-server-dom-turbopack packages, allowing threat actors to trigger out-of-memory exceptions or excessive CPU usage by sending specially crafted HTTP requests to server function endpoints.
date: "2026-07-24T21:16:16Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - react
  - denial-of-service
  - web
  - vulnerability
vendors:
  - Meta
products:
  - react-server-dom-webpack (versions 19.0.0-19.0.7, 19.1.0-19.1.8, 19.2.0-19.2.7)
  - react-server-dom-parcel (versions 19.0.0-19.0.7, 19.1.0-19.1.8, 19.2.0-19.2.7)
  - react-server-dom-turbopack (versions 19.0.0-19.0.7, 19.1.0-19.1.8, 19.2.0-19.2.7)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: A denial of service vulnerability could be triggered by sending specially crafted HTTP requests to server function endpoints, this could lead to out-of-memory exceptions or excessive CPU usage.
    confidence_band: high
cves:
  - id: CVE-2026-44907
    cvss: 7.5
    epss: 0.00329
references:
  - https://github.com/advisories/GHSA-wx67-qw84-cm4g
---

A high-severity denial of service (DoS) vulnerability, identified as CVE-2026-44907, has been discovered in several core React Server Component packages maintained by Meta. This vulnerability affects `react-server-dom-webpack`, `react-server-dom-parcel`, and `react-server-dom-turbopack` across various 19.x versions. Attackers can exploit this by sending maliciously crafted HTTP requests to application server function endpoints. Successful exploitation leads to severe resource consumption, including out-of-memory conditions or excessive CPU usage, causing the affected server to become unresponsive and resulting in a denial of service for legitimate users. This impacts applications that utilize React Server Components and do not run solely client-side. Immediate updates to patched versions (19.0.8, 19.1.9, 19.2.8) are crucial for all affected deployments.

## Attack Chain

1. An attacker identifies a web application running vulnerable versions of React Server Component packages.
2. The attacker crafts a specially designed HTTP request targeting a server function endpoint within the vulnerable React application.
3. This malicious request exploits a flaw in the `react-server-dom-*` package's processing logic.
4. The vulnerable server consumes excessive amounts of memory or CPU resources while attempting to handle the crafted request.
5. The server experiences resource exhaustion, leading to out-of-memory errors or extremely high CPU utilization.
6. The web application becomes unresponsive or crashes, resulting in a denial of service for all users.

## Impact

This denial of service vulnerability can lead to significant operational disruption for web applications utilizing affected React Server Components. If exploited, the server hosting the application will become unresponsive, potentially leading to downtime, loss of business continuity, and reputational damage. The impact specifically includes out-of-memory exceptions and excessive CPU usage, which effectively incapacitate the server's ability to serve legitimate user requests. While the source does not provide specific victim counts or targeted sectors, any organization deploying applications with the vulnerable `react-server-dom-*` packages is at risk.

## Recommendation

* **Patch CVE-2026-44907 immediately** by upgrading the `react-server-dom-webpack`, `react-server-dom-parcel`, and `react-server-dom-turbopack` packages to the fixed versions (19.0.8, 19.1.9, or 19.2.8, depending on your current major version).
* **Monitor web server logs** for unusual or malformed HTTP requests targeting server function endpoints after applying patches, to confirm proper mitigation and detect any residual exploitation attempts.
