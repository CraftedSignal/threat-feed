---
title: .NET Uncontrolled Resource Consumption Vulnerability (CVE-2026-26171)
slug: 2026-04-dotnet-dos
description: CVE-2026-26171 is a vulnerability in .NET that allows an unauthorized attacker to perform a denial-of-service attack over a network due to uncontrolled resource consumption.
date: "2026-04-15T12:00:00Z"
type: coverage
types:
  - coverage
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

CVE-2026-26171 is a denial-of-service vulnerability affecting the .NET framework. This vulnerability stems from uncontrolled resource consumption, allowing an unauthenticated remote attacker to exhaust server resources. The vulnerability was published on April 14, 2026. Successful exploitation can lead to server unresponsiveness or complete service disruption. While the specific attack vector is not detailed in the source document, similar vulnerabilities in .NET have been exploited via crafted network requests that trigger excessive memory allocation or CPU usage. This vulnerability could affect any application running on a vulnerable .NET framework version, making it critical for organizations to patch their systems.

## Attack Chain

1. An attacker identifies a .NET application running on a vulnerable system exposed to the network.
2. The attacker crafts a malicious network request designed to exploit the uncontrolled resource consumption vulnerability (CVE-2026-26171).
3. The crafted request is sent to the vulnerable .NET application.
4. The application processes the malicious request, triggering excessive resource allocation (e.g., memory or CPU).
5. Repeated or sustained malicious requests cause the server's resources to become exhausted.
6. Legitimate user requests are delayed or rejected due to resource exhaustion.
7. The .NET application becomes unresponsive, leading to a denial-of-service condition.
8. The server hosting the .NET application may crash, resulting in complete service disruption.

## Impact

Successful exploitation of CVE-2026-26171 can lead to a denial-of-service condition, rendering .NET applications and the services they provide unavailable. The impact ranges from temporary service disruption to complete server crashes. The vulnerability has a CVSS v3.1 score of 7.5, indicating a high severity. The number of affected applications depends on the prevalence of vulnerable .NET framework versions within an organization's infrastructure. If successfully exploited, this can lead to significant business interruption and reputational damage.

## Recommendation

*   Apply the patch provided by Microsoft for CVE-2026-26171 as soon as possible to remediate the vulnerability (https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26171).
*   Monitor network traffic for suspicious patterns indicative of denial-of-service attacks, such as a sudden surge in requests to .NET application endpoints. Deploy the Sigma rule detecting a high number of connections from a single source IP.
*   Implement resource monitoring on servers running .NET applications to detect unusual CPU or memory usage that may indicate exploitation attempts.
*   Review and harden network segmentation to limit the potential impact of a successful denial-of-service attack.
*   Consider using a Web Application Firewall (WAF) to filter malicious requests and mitigate potential exploitation attempts.
