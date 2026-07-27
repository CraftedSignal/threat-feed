---
title: Denial-of-Service Vulnerability in facil.io HTTP/1.1 Chunked Transfer Encoding Parser (CVE-2026-66731)
slug: 2026-07-facil-io-dos
description: 'An unauthenticated remote denial-of-service vulnerability exists in facil.io versions 0.7.5 through 0.7.6, allowing attackers to crash the server by sending a POST request with a ''Transfer-Encoding: chunked'' header containing a negative chunk size value, which corrupts internal state and leads to a fault.'
date: "2026-07-27T17:19:30Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - denial-of-service
  - web-vulnerability
  - facil.io
vendors:
  - facil.io
products:
  - facil.io 0.7.5
  - facil.io 0.7.6
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: facil.io ... contains a denial-of-service vulnerability ... allows unauthenticated remote attackers to crash the server
    confidence_band: high
cves:
  - id: CVE-2026-66731
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66731
---

A significant denial-of-service vulnerability, identified as CVE-2026-66731, has been discovered in the `facil.io` web application framework, specifically affecting versions 0.7.5 and 0.7.6. This vulnerability resides within the HTTP/1.1 chunked transfer encoding parser, located in `http1_parser.h`. Unauthenticated remote attackers can exploit this flaw by sending a specially crafted POST request. The request must include a `Transfer-Encoding: chunked` header with a chunk size value preceded by a minus sign. When processed, this negative value is erroneously converted into a very large positive integer by the parser. This incorrect interpretation corrupts the server's internal state, leading to attempts to access unmapped memory and subsequently causing the server process to crash. This vulnerability poses a direct threat to the availability of applications built with the affected `facil.io` versions.

## Attack Chain

1. An unauthenticated remote attacker identifies a web server running an application built with a vulnerable version of `facil.io` (0.7.5 or 0.7.6).
2. The attacker crafts a malicious HTTP POST request targeting the vulnerable server.
3. The crafted request includes the HTTP header `Transfer-Encoding: chunked`.
4. Within the body of the chunked transfer encoding, the attacker inserts a chunk size value that begins with a minus sign (e.g., `-1`).
5. The `facil.io` HTTP/1.1 chunked transfer encoding parser (located in `http1_parser.h`) attempts to process this malformed chunk size.
6. Due to a flaw in the parser's logic, the negative chunk size is incorrectly converted into a large positive integer value.
7. This erroneous interpretation corrupts the internal memory management state of the `facil.io` server process.
8. The server process attempts to access unmapped memory locations, leading to a segmentation fault and ultimately crashing the server, resulting in a denial-of-service.

## Impact

Successful exploitation of CVE-2026-66731 results in a complete denial-of-service (DoS) for any application running on affected `facil.io` servers. Attackers can repeatedly crash the server with minimal effort, rendering services unavailable to legitimate users. While no specific victim counts or targeted sectors are mentioned, any organization utilizing `facil.io` versions 0.7.5 or 0.7.6 for their web applications is at risk. The direct consequence is service disruption, which can lead to significant operational losses, reputational damage, and potential financial impact for affected organizations. The vulnerability requires no authentication, making it particularly easy to exploit remotely.

## Recommendation

* Patch CVE-2026-66731 by updating `facil.io` to a version beyond 0.7.6, as soon as a fix is available, on all affected servers immediately.
* Implement Web Application Firewalls (WAFs) or intrusion prevention systems (IPS) to detect and block malformed HTTP requests, especially those with unusual `Transfer-Encoding` header content.
