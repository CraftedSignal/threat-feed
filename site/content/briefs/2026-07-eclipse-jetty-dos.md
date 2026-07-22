---
title: Eclipse Jetty Denial of Service Vulnerability via 100-Continue Requests (CVE-2024-7708)
slug: 2026-07-eclipse-jetty-dos
description: A memory leak vulnerability, CVE-2024-7708, in Eclipse Jetty's server handling of HTTP 100-Continue requests can be exploited by an attacker to trigger an OutOfMemory error, leading to a Denial of Service state for affected servers.
date: "2026-07-22T23:00:19Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:eclipse:jetty:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - webserver
  - memory-leak
vendors:
  - Eclipse
products:
  - Jetty 10
  - Jetty 11
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: Server handling of 100-Continue requests can lead to memory leak that can be abused to cause a Denial of Service state.
    confidence_band: high
cves:
  - id: CVE-2024-7708
    cvss: 7.5
    epss: 0.00252
references:
  - https://github.com/advisories/GHSA-9299-c6m4-mjhc
  - https://github.com/jetty/jetty.project/pull/12156
---

A high-severity memory leak vulnerability (CVE-2024-7708) has been identified in Eclipse Jetty, affecting versions 10.0.0 through 10.0.22 and 11.0.0 through 11.0.22. The flaw arises from the server's handling of HTTP `100-Continue` requests, specifically when the server attempts to read a request body but ends up reading zero bytes. This condition, which can be triggered by slow network conditions or malicious client behavior, causes a buffer to leak memory. An unauthenticated attacker can exploit this by repeatedly sending specially crafted requests, leading to memory exhaustion and an eventual `OutOfMemory` error. This resource depletion can render the Jetty server unresponsive, resulting in a Denial of Service (DoS) for legitimate users. There are no known workarounds other than patching.

## Attack Chain

1. An unauthenticated attacker identifies a public-facing server running a vulnerable version of Eclipse Jetty (e.g., Jetty 11.0.22).
2. The attacker initiates an HTTP POST request to the vulnerable Jetty server, including the `Expect: 100-Continue` header.
3. The attacker then manipulates network conditions or client behavior to ensure that the server, after sending a `100 Continue` response, attempts to read the request body but reads zero bytes.
4. This specific condition triggers a memory leak within the Jetty server process, where an allocated buffer is not properly released.
5. The attacker continuously sends a high volume of these specially crafted HTTP requests to the vulnerable server.
6. Repeated exploitation of the memory leak causes a cumulative depletion of the server's available memory resources.
7. Eventually, the Jetty server experiences an `OutOfMemory` error, leading to its crash or an unresponsive state.
8. The Jetty server becomes unavailable to legitimate users, resulting in a Denial of Service.

## Impact

Successful exploitation of CVE-2024-7708 results in a Denial of Service (DoS) condition on the vulnerable Eclipse Jetty server. This can lead to the server process crashing or becoming entirely unresponsive, preventing legitimate users from accessing services or applications hosted on it. The impact includes service unavailability, potential data loss (if not properly handled during the crash), and reputational damage for affected organizations. All applications and services relying on vulnerable Jetty instances are at risk. There is no information available regarding the number of victims or specific sectors targeted, but any organization using unpatched Jetty 10 or 11 versions is susceptible.

## Recommendation

* Patch CVE-2024-7708 immediately by upgrading all affected Jetty servers to version 11.0.23 or 10.0.23.
* Monitor `webserver` logs for unusual patterns or high volumes of HTTP requests containing the `Expect: 100-Continue` header originating from single or suspicious IP addresses.
