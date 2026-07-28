---
title: Null Pointer Dereference Vulnerability in TinyWeb
slug: 2026-07-tinyweb-null-dereference
description: A null pointer dereference vulnerability, CVE-2026-67184, in TinyWeb through version 0.0.8 allows unauthenticated remote attackers to crash worker processes by sending a malformed HTTP request line with an invalid version string, leading to a denial of service.
date: "2026-07-28T17:22:09Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - web-vulnerability
  - denial-of-service
  - cve
vendors:
  - TinyWeb
products:
  - TinyWeb (<= 0.0.8)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: terminates the worker process and, when repeated across all workers, takes the server permanently offline until manually restarted
    confidence_band: high
cves:
  - id: CVE-2026-67184
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67184
---

TinyWeb versions up to and including 0.0.8 are vulnerable to a null pointer dereference, tracked as CVE-2026-67184. This critical vulnerability allows unauthenticated remote attackers to trigger a denial of service by sending a specially crafted HTTP request. The attack is initiated by providing a malformed HTTP request line that contains an invalid version string. When the `HttpParser::execute()` function processes this invalid input, it fails to correctly allocate the `Url` object, leaving its pointer `NULL`. Subsequently, the `buildResponse()` function attempts to dereference this `NULL` pointer without proper validation, leading to a Segmentation Fault (`SIGSEGV`). This crash terminates the worker process, and if sufficient malformed requests are sent, all worker processes can be brought down, rendering the TinyWeb server permanently offline until manual intervention. This poses a significant threat to the availability of services running on affected TinyWeb instances.

## Attack Chain

1. An unauthenticated remote attacker sends an HTTP request to a vulnerable TinyWeb server (version 0.0.8 or earlier).
2. The attacker crafts the HTTP request line to include an invalid or malformed version string (e.g., `GET / HTTP/MALFORMED`).
3. The TinyWeb server's `HttpParser::execute()` function attempts to parse the incoming malformed HTTP request.
4. Due to the invalid version string, the `HttpParser::execute()` function fails to allocate the `Url` object, leaving the `url` pointer as `NULL`.
5. The server then proceeds to call the `buildResponse()` function to formulate a response.
6. Within `buildResponse()`, an attempt is made to dereference the `NULL` `url` pointer without checking the `valid_requ` flag.
7. This `NULL` pointer dereference triggers a Segmentation Fault (`SIGSEGV`), causing the worker process handling the request to crash and terminate.
8. By repeatedly sending such malformed requests, the attacker can crash all available worker processes, leading to a complete denial-of-service for the TinyWeb server until it is manually restarted.

## Impact

Successful exploitation of CVE-2026-67184 leads to a complete denial-of-service for the TinyWeb server. Attackers can remotely crash worker processes by sending malformed HTTP requests, eventually taking the server permanently offline. This directly impacts the availability of any web services hosted by TinyWeb, disrupting operations and potentially causing significant financial and reputational damage. There is no specific information on the number of victims or targeted sectors, but any organization using TinyWeb through version 0.0.8 for their web infrastructure is at risk.

## Recommendation

* Patch TinyWeb immediately to a version greater than 0.0.8 to remediate CVE-2026-67184.
* Implement robust monitoring of web server logs for indicators of malformed HTTP requests, specifically looking for unusual or invalid HTTP version strings.
* Deploy network intrusion detection systems (NIDS) to identify and block HTTP requests containing non-standard or malformed version strings before they reach web servers.
