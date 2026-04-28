---
title: CoreDNS DoH GET Query Denial-of-Service
slug: 2024-01-08-coredns-doh-dos
description: CoreDNS is vulnerable to a denial-of-service attack where processing oversized DNS-over-HTTPS GET requests exhausts resources prior to returning an error.
date: "2024-01-08T14:30:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - cve
  - dos
  - coredns
vendors:
  - CoreDNS
products:
  - CoreDNS
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
references:
  - https://github.com/advisories/GHSA-63cw-r7xf-jmwr
rules:
  - title: Detect CoreDNS DoH GET Oversized DNS Query
    description: Detects HTTP GET requests to the /dns-query endpoint with abnormally large 'dns' query parameters, indicating a potential denial-of-service attempt.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
  - title: Detect CoreDNS DoH GET Request with High URL Length
    description: Detects HTTP GET requests with unusually long URLs targeting the /dns-query endpoint, potentially indicating a DoH-based denial-of-service attack.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CoreDNS is susceptible to a denial-of-service vulnerability affecting its DNS-over-HTTPS (DoH) GET request handling. The vulnerability, identified as CVE-2026-32936, stems from the server's excessive processing of oversized `dns=` query parameters in GET requests to the `/dns-query` endpoint. An unauthenticated attacker can exploit this by sending specially crafted, oversized requests, forcing the server to expend significant CPU resources, allocate large amounts of memory, and increase garbage collection overhead before ultimately rejecting the request with a `400 Bad Request` error. This pre-validation processing weakness can degrade the server's performance, impacting its ability to respond to legitimate requests, and potentially leading to a complete denial of service, especially in memory-constrained environments. The vulnerability affects CoreDNS versions prior to 1.14.3.

## Attack Chain

1.  The attacker crafts an HTTP GET request to the `/dns-query` endpoint.
2.  The crafted request includes a `dns=` query parameter with an extremely large, base64 encoded value.
3.  CoreDNS receives the request and parses the HTTP request line using `net/http.readRequest`.
4.  The server parses the URL and extracts the value of the `dns` query parameter via `req.URL.Query()` within the `requestToMsgGet` function.
5.  The extracted base64-encoded value is passed to the `base64ToMsg` function for decoding.
6.  The `base64ToMsg` function uses `b64Enc.DecodeString()` to decode the oversized base64 string, consuming significant CPU and memory.
7.  The decoded data is then passed to `m.Unpack()` to unpack it into a DNS message, further increasing resource consumption.
8.  Only after these resource-intensive operations, CoreDNS determines that the request is invalid and returns a `400 Bad Request` error, having already expended significant server resources.

## Impact

Successful exploitation of this vulnerability can lead to a denial-of-service condition. Attackers can repeatedly send oversized DoH GET requests, leading to:
*   Elevated CPU consumption, potentially causing performance degradation for other services.
*   Large transient memory allocations, leading to increased garbage collection pressure and potential memory exhaustion.
*   Higher peak resident memory usage, impacting overall system stability.
*   Degraded throughput and responsiveness for legitimate DNS queries.
*   Ultimately, a denial of service, especially in resource-constrained or heavily loaded deployments.

## Recommendation

*   Deploy the Sigma rule `Detect CoreDNS DoH GET Oversized DNS Query` to detect exploitation attempts by monitoring HTTP requests with abnormally large DNS query parameters.
*   Upgrade CoreDNS to version 1.14.3 or later to patch CVE-2026-32936.
*   Implement rate limiting for the `/dns-query` endpoint to mitigate the impact of a large volume of malicious requests.
*   Consider disabling the DoH GET method and only allowing DoH POST, which has built-in size limitations, as a temporary workaround.
