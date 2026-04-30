---
title: React Server Components Denial of Service Vulnerability (CVE-2026-23869)
slug: 2026-04-react-dos
description: A denial of service vulnerability, CVE-2026-23869, exists in React Server Components due to excessive CPU usage triggered by specially crafted HTTP requests to Server Function endpoints, potentially leading to service disruption.
date: "2026-04-08T20:16:23Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - CVE-2026-23869
  - denial-of-service
  - react
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-23869
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-23869
rules:
  - title: Detect Suspicious React Server Function Requests
    description: Detects potentially malicious HTTP requests targeting React Server Function endpoints that may lead to a denial-of-service condition.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
  - title: Detect High CPU Usage Associated with React Server Components
    description: Detects excessive CPU usage on a web server potentially caused by a denial-of-service attack targeting React Server Components.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-23869 is a denial-of-service (DoS) vulnerability affecting React Server Components. Specifically, the vulnerability impacts the `react-server-dom-parcel`, `react-server-dom-turbopack`, and `react-server-dom-webpack` packages in versions 19.0.0 through 19.0.4, 19.1.0 through 19.1.5, and 19.2.0 through 19.2.4. An attacker can exploit this vulnerability by sending specially crafted HTTP requests to Server Function endpoints. These malicious requests cause excessive CPU utilization on the server, potentially leading to service degradation or unavailability. The CPU usage can remain high for up to a minute before an error is thrown. This vulnerability poses a significant risk to applications utilizing the affected React Server Components, as it allows for relatively easy disruption of service.

## Attack Chain

1.  The attacker identifies a server running a vulnerable version of React Server Components (19.0.0-19.0.4, 19.1.0-19.1.5, or 19.2.0-19.2.4).
2.  The attacker discovers a Server Function endpoint within the React application.
3.  The attacker crafts a malicious HTTP request specifically designed to trigger the vulnerability.
4.  The attacker sends the crafted HTTP request to the Server Function endpoint.
5.  Upon receiving the malicious request, the server begins to experience excessive CPU usage.
6.  The CPU usage remains elevated for a significant period (up to one minute).
7.  Eventually, the server throws an error due to the excessive processing load.
8.  The elevated CPU usage and eventual error cause a denial of service, making the application unresponsive or unavailable to legitimate users.

## Impact

Successful exploitation of CVE-2026-23869 can lead to a denial-of-service condition, rendering affected React applications unavailable. This can disrupt business operations, damage reputation, and potentially lead to financial losses. The severity of the impact depends on the criticality of the affected application and the duration of the service disruption. While the precise number of potential victims is unknown, any organization using the vulnerable React Server Components is at risk.

## Recommendation

*   Upgrade to a patched version of `react-server-dom-parcel`, `react-server-dom-turbopack`, or `react-server-dom-webpack` to remediate CVE-2026-23869.
*   Deploy the Sigma rule "Detect Suspicious React Server Function Requests" to monitor for potentially malicious HTTP requests targeting Server Function endpoints, based on HTTP request patterns.
*   Monitor web server logs for unusually high CPU usage correlated with requests to Server Function endpoints.
