---
title: OpenTelemetry-Go Multi-Value Baggage Header Extraction DoS Vulnerability (CVE-2026-29181)
slug: 2026-04-opentelemetry-dos
description: A vulnerability in OpenTelemetry-Go related to the extraction of multi-value baggage headers can lead to excessive resource allocation, resulting in a remote denial-of-service amplification.
date: "2026-04-29T07:33:41Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - dos
  - opentelemetry
  - cve-2026-29181
products:
  - OpenTelemetry-Go
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
cves:
  - id: CVE-2026-29181
    cvss: 7.5
    epss: 0.00052
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-29181
rules:
  - title: Detect Suspicious Baggage Header Size
    description: Detects HTTP requests with unusually large baggage headers, potentially indicating a denial-of-service attempt.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - webserver
      - linux
  - title: Detect High Volume of Requests with Baggage Header
    description: Detects a high volume of HTTP requests containing baggage headers from a single source IP within a short time frame, potentially indicating a denial-of-service attempt.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-29181 describes a vulnerability within the OpenTelemetry-Go library. Specifically, the manner in which the library handles HTTP requests containing multiple values within the `baggage` header can be exploited. An attacker can craft malicious requests with excessively large or numerous baggage values, leading to excessive memory allocations on the server. This resource exhaustion can ultimately result in a denial-of-service condition, impacting the availability of services relying on the vulnerable OpenTelemetry-Go component. This vulnerability highlights the importance of careful input validation and resource management in telemetry libraries.

## Attack Chain

1. An attacker identifies a service using a vulnerable version of OpenTelemetry-Go.
2. The attacker crafts an HTTP request targeting an endpoint monitored by OpenTelemetry.
3. The crafted HTTP request includes a `baggage` header containing numerous values or excessively large individual values.
4. The OpenTelemetry-Go library attempts to extract and process these baggage values upon receiving the request.
5. The baggage extraction process triggers excessive memory allocations due to the large number or size of baggage values.
6. Repeated requests of this nature rapidly consume available server memory.
7. The server's performance degrades significantly as it struggles to allocate memory.
8. Ultimately, the server becomes unresponsive, resulting in a denial-of-service condition, making the service unavailable to legitimate users.

## Impact

Successful exploitation of CVE-2026-29181 leads to a denial-of-service condition. The number of affected services depends on the prevalence of vulnerable OpenTelemetry-Go library versions in production environments. Affected services become unavailable, disrupting normal operations and potentially leading to financial losses or reputational damage. The impact is amplified if critical infrastructure components rely on the vulnerable services.

## Recommendation

*   Upgrade OpenTelemetry-Go to a patched version that addresses CVE-2026-29181 to prevent excessive memory allocation.
*   Deploy the Sigma rule `Detect Suspicious Baggage Header Size` to identify potentially malicious requests exploiting this vulnerability.
*   Implement rate limiting on HTTP endpoints that are monitored by OpenTelemetry to mitigate the impact of denial-of-service attacks.
*   Review and adjust memory allocation limits for services using OpenTelemetry-Go to prevent resource exhaustion.
