---
brief_id: brief-2026-06-quic-go-memory-exhaustion-dos
event_id: brief-2026-06-quic-go-memory-exhaustion-dos
revision: 1
activity_at: "2026-06-14T22:37:58Z"
title: 'CVE-2026-40898: quic-go HTTP/3 Memory Exhaustion DoS'
slug: 2026-06-quic-go-memory-exhaustion-dos
description: A vulnerability in quic-go, an implementation of the QUIC protocol in Go, allows a remote attacker to cause a denial-of-service (DoS) condition by sending specially crafted QPACK-encoded HEADERS frames with large trailer field sections, leading to excessive memory allocation in affected HTTP/3 client and server implementations prior to version 0.59.1.
date: "2026-06-14T22:37:58Z"
lastmod: "2026-10-22T09:35:56Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
cpes:
  - cpe:2.3:a:quic-go_project:quic-go:*:*:*:*:*:*:*:*
has_poc: true
tags:
  - denial-of-service
  - vulnerability
  - network
  - http3
  - quic
  - golang
vendors:
  - quic-go_project
products:
  - quic-go (<= 0.56.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-40898
    cvss: 5.3
    epss: 0.00488
    kev_status: "false"
  - id: CVE-2025-64702
    cvss: 5.3
    epss: 0.00364
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40898
  - https://thehackernews.com/2026/10/new-qpack-flaws-can-crash-http3-servers.html
updates:
  - at: "2026-10-22T09:35:56Z"
    level: L2
    summary: poc_available; quic-go version <= 0.56.0
    sources:
      - the-hacker-news
    source_urls:
      - https://thehackernews.com/2026/10/new-qpack-flaws-can-crash-http3-servers.html
---

CVE-2026-40898 details a severe denial-of-service (DoS) vulnerability affecting `quic-go`, a popular open-source implementation of the QUIC protocol in Go. Prior to version 0.59.1, both HTTP/3 client and server implementations are susceptible to excessive memory allocation. This occurs when an attacker sends a QPACK-encoded HEADERS frame containing a large trailer field section with numerous unique field names or extensive values. The `quic-go` library, failing to enforce limits on the decoded field section size (only on the compressed frame size), attempts to construct an `http.Header` object using an exorbitant amount of memory. This can lead to system resource exhaustion, causing applications using `quic-go` to crash or become unresponsive. The vulnerability is similar to CVE-2025-64702 but specifically targets HTTP trailers.

## Attack Chain

1.  **Attacker Establishes QUIC Connection:** A remote attacker identifies a target system or application utilizing a `quic-go` based HTTP/3 service and initiates a QUIC connection.
2.  **Malicious QPACK Frame Crafting:** The attacker constructs a specially malformed QPACK-encoded HEADERS frame, embedding a significantly large trailer field section with a high count of unique field names and/or large data values.
3.  **Frame Transmission:** The attacker transmits this crafted QPACK HEADERS frame over the established QUIC connection to the vulnerable `quic-go` HTTP/3 service.
4.  **Vulnerable Processing:** The `quic-go` library, operating on versions prior to 0.59.1, begins to process and decode the incoming malicious QPACK HEADERS frame.
5.  **Excessive Memory Allocation:** Due to the absence of decoded field section size limits, the `quic-go` implementation allocates an inordinate amount of memory to build the `http.Header` object representing the large trailer section.
6.  **Resource Exhaustion:** The continuous and unchecked memory allocation rapidly consumes available system memory, leading to resource exhaustion on the host running the `quic-go` application.
7.  **Application Crash/Unavailability:** The `quic-go` based application either crashes, becomes unresponsive, or the entire host experiences a denial-of-service, disrupting critical services.

## Impact

Successful exploitation of CVE-2026-40898 directly results in a denial-of-service (DoS) condition for applications leveraging the `quic-go` library for HTTP/3 communication. This can manifest as application crashes, frequent service restarts, or complete system unresponsiveness due to resource exhaustion (specifically memory). While specific victim counts or sectors are not available, any organization deploying services or clients built with vulnerable versions of `quic-go` (prior to 0.59.1) is at risk. The operational impact could range from temporary service disruption to prolonged outages, depending on the targeted application's criticality and the attacker's sustained efforts.

## Recommendation

*   **Patch CVE-2026-40898 Immediately:** Upgrade all applications using the `quic-go` library to version 0.59.1 or later to mitigate CVE-2026-40898.
*   **Deploy Sigma Rules:** Deploy the provided Sigma rules to your SIEM solution to detect application crashes and excessive restarts that could indicate CVE-2026-40898 exploitation.
*   **Monitor HTTP/3 Service Health:** Implement robust monitoring for applications functioning as HTTP/3 servers or clients to detect unusual memory consumption, high CPU usage, or unexpected process terminations.
