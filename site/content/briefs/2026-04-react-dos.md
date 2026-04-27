---
title: React Server Components Denial of Service Vulnerability (CVE-2026-23869)
slug: 2026-04-react-dos
description: A denial of service vulnerability, CVE-2026-23869, exists in React Server Components due to excessive CPU usage triggered by specially crafted HTTP requests to Server Function endpoints, potentially leading to service disruption.
date: "2026-04-08T20:16:23Z"
severities:
  - high
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

CVE-2026-23869 is a denial-of-service (DoS) vulnerability affecting React Server Components. Specifically, the vulnerability impacts the `react-server-dom-parcel`, `react-server-dom-turbopack`, and `react-server-dom-webpack` packages in versions 19.0.0 through 19.0.4, 19.1.0 through 19.1.5, and 19.2.0 through 19.2.4. An attacker can exploit this vulnerability by sending specially crafted HTTP requests to Server Function endpoints. These malicious requests cause excessive CPU utilization on the…
