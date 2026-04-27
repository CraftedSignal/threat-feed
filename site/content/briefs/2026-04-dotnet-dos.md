---
title: .NET Uncontrolled Resource Consumption Vulnerability (CVE-2026-26171)
slug: 2026-04-dotnet-dos
description: CVE-2026-26171 is a vulnerability in .NET that allows an unauthorized attacker to perform a denial-of-service attack over a network due to uncontrolled resource consumption.
date: "2026-04-15T12:00:00Z"
severities:
  - high
tags:
  - CVE-2026-26171
  - dotnet
  - denial-of-service
  - dos
  - resource-consumption
cves:
  - id: CVE-2026-26171
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-26171
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26171
rules:
  - title: High Number of Connections from Single Source IP
    description: Detects a high number of network connections originating from a single source IP address, potentially indicating a denial-of-service attack.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - windows
rules_count: 1
---

CVE-2026-26171 is a denial-of-service vulnerability affecting the .NET framework. This vulnerability stems from uncontrolled resource consumption, allowing an unauthenticated remote attacker to exhaust server resources. The vulnerability was published on April 14, 2026. Successful exploitation can lead to server unresponsiveness or complete service disruption. While the specific attack vector is not detailed in the source document, similar vulnerabilities in .NET have been exploited via crafted…
