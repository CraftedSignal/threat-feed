---
title: Phoenix Long-Poll Transport Denial-of-Service Vulnerability
slug: 2024-11-phoenix-longpoll-dos
description: An unauthenticated denial-of-service vulnerability in Phoenix's long-poll transport allows a remote client to exhaust server memory by sending a series of crafted HTTP requests, affecting LiveView apps with a public Longpoll socket or Phoenix.Socket with longpoll option.
date: "2024-11-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - dos
  - phoenix
  - webserver
vendors:
  - Erlang
products:
  - Phoenix
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499.001
    technique_name: 'Endpoint Denial of Service: Resource Exhaustion'
cves:
  - id: CVE-2026-32689
    epss: 0.00045
references:
  - https://github.com/advisories/GHSA-628h-q48j-jr6q
  - https://cna.erlef.org/cves/CVE-2026-32689.html
rules:
  - title: Detect CVE-2026-32689 Exploitation Attempt — High Volume NDJSON POST Requests
    description: Detects CVE-2026-32689 exploitation attempt — monitors for a high volume of application/x-ndjson POST requests to the long-poll endpoint, which could indicate an attempt to exhaust server memory.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - webserver
  - title: Detect CVE-2026-32689 Exploitation Attempt — NDJSON POST with Large Body
    description: Detects CVE-2026-32689 exploitation attempt — Identifies POST requests to the long-poll endpoint with 'application/x-ndjson' content type and a large request body, indicative of a memory exhaustion attempt.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - webserver
rules_count: 2
---

A denial-of-service vulnerability has been identified in the long-poll transport mechanism of the Phoenix framework. This vulnerability, designated as CVE-2026-32689, allows an unauthenticated remote attacker to cause a significant memory allocation on the server by sending malicious HTTP requests. The flaw stems from an unoptimized code path in the `application/x-ndjson` POST handling within the LongPoll transport. Since obtaining a session token requires only a GET request with a matching `Origin` header, exploitation is unauthenticated. This issue has been present in newly generated Phoenix projects since version 1.7.11, potentially exposing a wide range of applications to denial-of-service attacks. The affected versions are Phoenix versions >= 1.7.0 and < 1.7.22, as well as >= 1.8.0 and < 1.8.6.

## Attack Chain

1. Attacker sends an HTTP GET request to the long-poll endpoint with a valid `Origin` header.
2. The server responds with a session token.
3. Attacker sends multiple concurrent HTTP POST requests with the `application/x-ndjson` content type to the long-poll endpoint, including the session token.
4. The server receives the POST requests and processes them through the unoptimized code path in the LongPoll transport.
5. The server allocates a large amount of memory for each request due to the NDJSON body splitting.
6. The memory consumption increases rapidly as the attacker sends more requests.
7. The server's memory resources are exhausted, leading to a denial-of-service condition.
8. Legitimate users are unable to access the application due to the server's unavailability.

## Impact

Successful exploitation of this vulnerability can lead to a complete denial-of-service, rendering Phoenix-based applications unresponsive. Applications using LiveView with public Longpoll sockets or `Phoenix.Socket` with the longpoll option are vulnerable. Because longpoll has been enabled by default in Phoenix projects since version 1.7.11, many applications are likely affected. The impact is a temporary outage, potentially leading to data loss or service disruption.

## Recommendation

*   Upgrade to Phoenix version 1.7.22 or 1.8.6 or later to patch CVE-2026-32689 and mitigate the denial-of-service vulnerability.
*   Deploy the Sigma rule "Detect CVE-2026-32689 Exploitation Attempt — High Volume NDJSON POST Requests" to identify potential exploitation attempts by monitoring for a high volume of `application/x-ndjson` POST requests to the long-poll endpoint.
*   Monitor web server logs for an unusual number of POST requests with the `application/x-ndjson` content type, looking for potential indicators of exploitation.
