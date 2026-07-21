---
title: Denial of Service in websocket-driver-ruby via Malformed Host Header (CVE-2026-61666)
slug: 2026-07-websocket-driver-dos
description: A denial of service vulnerability (CVE-2026-61666) exists in the websocket-driver-ruby library when used to implement a WebSocket server via `WebSocket::Driver.server()`, allowing a remote attacker to send a malformed `Host` header causing a `URI::InvalidURIError` exception and subsequent server process crash if unhandled.
date: "2026-07-21T18:36:13Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - vulnerability
  - ruby
  - webserver
vendors:
  - RubyGems
products:
  - websocket-driver (< 0.8.2)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: A client can cause the server to crash by sending a `Host` header that is not a valid `host[:port]` string. [...] this can cause the server process to crash if the application does not catch the error from the `parse()` method itself.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-2x63-gw47-w4mm
rules:
  - title: Detects CVE-2026-61666 Exploitation - Malformed HTTP Host Header
    description: Detects attempts to exploit CVE-2026-61666 by sending HTTP requests with a malformed `Host` header, specifically one containing a space character, which can lead to a denial of service in `websocket-driver-ruby`.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499
    data_sources:
      - webserver
rules_count: 1
---

A high-severity denial of service (DoS) vulnerability, tracked as CVE-2026-61666, has been identified in the `websocket-driver-ruby` library, specifically affecting versions prior to 0.8.2. This vulnerability impacts applications that use the library to implement a WebSocket server via the `WebSocket::Driver.server()` method. An unauthenticated remote attacker can exploit this flaw by sending an HTTP request containing a malformed `Host` header, one that does not conform to the standard `host[:port]` string format. This malformed header triggers a `URI::InvalidURIError` exception within the library's parsing logic. If the vulnerable application does not explicitly catch this specific exception, the unhandled error will cause the server process to crash, leading to a complete denial of service for the affected WebSocket server. The issue has been patched in version 0.8.2, which includes error handling for invalid `Host` headers.

## Attack Chain

1. An attacker identifies a target application running a WebSocket server using the `websocket-driver` library (versions prior to 0.8.2) through the `WebSocket::Driver.server()` method.
2. The attacker crafts a standard HTTP GET request intended for the WebSocket server.
3. The crafted request includes a `Host` header that is malformed, specifically containing characters or structures that violate the `host[:port]` format (e.g., `Host: invalid host.com`).
4. The `websocket-driver` library's internal parsing mechanisms attempt to process the malformed `Host` header received from the attacker's request.
5. During the parsing of the malformed `Host` header, the library encounters an invalid URI string, which raises a `URI::InvalidURIError` exception.
6. Because the vulnerable application utilizing the `websocket-driver` library does not have specific error handling in place to catch the `URI::InvalidURIError` exception from the `parse()` method, the exception propagates unhandled.
7. The unhandled exception causes the entire WebSocket server process to terminate abruptly, leading to a crash and making the service unavailable to legitimate users.
8. The attacker successfully achieves a denial of service, rendering the WebSocket server inoperable until manually restarted.

## Impact

The successful exploitation of CVE-2026-61666 results in a denial of service (DoS) for affected WebSocket servers. When a malformed `Host` header is processed, a `URI::InvalidURIError` is raised. If the application does not explicitly catch this error, the server process will crash, making the WebSocket service completely unavailable. This can lead to significant downtime for any services relying on the WebSocket communication, disrupting real-time functionalities, data synchronization, or interactive applications. There are no specific victim numbers or targeted sectors mentioned, but any organization using the vulnerable `websocket-driver` gem in a server capacity is at risk.

## Recommendation

* Patch all instances of `websocket-driver` to version 0.8.2 or later immediately to mitigate CVE-2026-61666.
* Deploy the provided Sigma rule to your SIEM to detect attempts at exploiting CVE-2026-61666 by identifying malformed `Host` headers.
* Ensure webserver logs capture full HTTP request headers, especially the `Host` header, to enable detection of the patterns specified in the Sigma rule.
