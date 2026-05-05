---
title: Prometheus Remote Read Endpoint Denial-of-Service Vulnerability
slug: 2026-05-prometheus-dos
description: The Prometheus remote read endpoint is vulnerable to denial of service due to a missing validation of the declared decoded length in snappy-compressed request bodies, allowing unauthenticated attackers to exhaust memory resources.
date: "2026-05-05T19:34:58Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - prometheus
  - snappy
vendors:
  - Prometheus
products:
  - go/github.com/prometheus/prometheus (< 0.311.3)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-42154
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-8rm2-7qqf-34qm
rules:
  - title: Detect Suspicious Prometheus Snappy Request Size
    description: Detects abnormally large request sizes to the /api/v1/read endpoint, potentially indicating a denial-of-service attempt via crafted snappy payload.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499
    data_sources:
      - webserver
      - linux
  - title: Detect Prometheus Unauthenticated Remote Read Access
    description: Detects access to the Prometheus remote read endpoint without authentication, which can be exploited if combined with CVE-2026-42154.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1588.006
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Prometheus monitoring system is susceptible to a denial-of-service (DoS) vulnerability affecting the `/api/v1/read` endpoint. This flaw, identified as CVE-2026-42154, stems from the lack of validation of the declared decoded length within snappy-compressed request bodies. An unauthenticated attacker can exploit this vulnerability by sending a specially crafted, small payload. This payload triggers a massive heap allocation for each request, rapidly consuming available memory resources. Under concurrent load, this leads to memory exhaustion and subsequent crashing of the Prometheus process. The vulnerability impacts Prometheus versions prior to 3.11.3 and 3.5.3 LTS.

## Attack Chain

1. An attacker identifies a vulnerable Prometheus instance exposing the `/api/v1/read` endpoint.
2. The attacker crafts a small HTTP POST request containing a snappy-compressed body.
3. The crafted payload declares an extremely large decoded length within the snappy header.
4. The attacker sends the malicious HTTP POST request to the `/api/v1/read` endpoint.
5. The Prometheus server receives the request and attempts to decompress the snappy data.
6. Due to the missing validation, the server allocates a large chunk of memory based on the declared (but invalid) decoded length.
7. The attacker sends numerous concurrent requests, each triggering a large memory allocation.
8. The Prometheus server's memory is rapidly exhausted, leading to a crash and denial of service.

## Impact

Successful exploitation of this vulnerability results in a denial-of-service condition, rendering the Prometheus monitoring system unavailable. This can disrupt monitoring capabilities, leading to delayed detection of critical system issues and potentially impacting incident response. The vulnerability is unauthenticated, increasing the risk of exploitation. The number of victims depends on the exposure of vulnerable Prometheus instances; any instance accessible over the network is potentially vulnerable.

## Recommendation

*   Upgrade Prometheus instances to version 3.11.3 or 3.5.3 LTS or later to remediate CVE-2026-42154.
*   For users unable to upgrade immediately, implement a reverse proxy or firewall to require authentication before requests reach the `/api/v1/read` endpoint as a temporary workaround.
*   Deploy the Sigma rule "Detect Suspicious Prometheus Snappy Request Size" to identify potential exploitation attempts targeting the vulnerable endpoint.
*   Monitor web server logs for unusually large POST requests to the `/api/v1/read` endpoint, potentially indicating exploitation attempts.
