---
title: FreeRDP Resource Exhaustion via Malicious HTTP Chunked Encoding
slug: 2026-08-freerdp-dos
description: FreeRDP versions prior to 3.29.0 contain a vulnerability in the http_response_recv_body function that allows remote attackers to trigger memory exhaustion via oversized chunked HTTP responses.
date: "2026-08-01T13:52:08Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - denial-of-service
  - vulnerability
  - remote-access
vendors:
  - FreeRDP
products:
  - FreeRDP (Before 3.29.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Attackers controlling a malicious RD Gateway endpoint can send oversized chunked response bodies to exhaust client memory resources without triggering the configured size limit.
    confidence_band: high
cves:
  - id: CVE-2026-67297
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67297
  - https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-2c6r-4pr4-9x8m
  - https://www.vulncheck.com/advisories/freerdp-before-resource-exhaustion-via-chunked-http-response
---

FreeRDP versions before 3.29.0 are vulnerable to a resource exhaustion flaw (CVE-2026-67297) when processing HTTP responses that utilize `Transfer-Encoding: chunked`. The vulnerability resides within the `http_response_recv_body()` function, which fails to correctly enforce the `RESPONSE_SIZE_LIMIT` during the assembly of chunked data. An attacker controlling a malicious Remote Desktop (RD) Gateway endpoint can leverage this flaw to send specifically crafted, oversized HTTP responses to a connecting client. This causes the client's memory consumption to grow unbounded, ultimately leading to a denial-of-service (DoS) state for the FreeRDP process. Because this occurs at the gateway negotiation phase, it can be triggered by a remote attacker without prior authentication, posing a significant risk to organizations relying on FreeRDP-based clients for remote connectivity.

## Attack Chain

1. Attacker configures a malicious server acting as an RD Gateway.
2. Victim initiates a standard connection attempt to the malicious RD Gateway using an affected version of FreeRDP.
3. The malicious server initiates the HTTP handshake for the RD Gateway protocol.
4. The malicious server issues a response header indicating `Transfer-Encoding: chunked`.
5. The attacker sends a continuous stream of large data chunks, bypassing the expected `RESPONSE_SIZE_LIMIT` check in `http_response_recv_body()`.
6. The client process allocates memory to buffer the incoming chunked data.
7. Sustained delivery of chunks forces the client process to reach memory limits, resulting in a crash or system instability.
8. The final objective is the denial-of-service of the remote access client on the victim machine.

## Impact

Successful exploitation results in a denial-of-service condition for the FreeRDP client process. This can disrupt remote access for users who rely on this software for connectivity to corporate environments. The vulnerability is exploitable remotely without user interaction or authentication, increasing the risk of service interruption across an enterprise deployment.

## Recommendation

1. Upgrade all FreeRDP client installations to version 3.29.0 or later to ensure the `RESPONSE_SIZE_LIMIT` is correctly enforced.
2. Audit client configurations to verify that only trusted and authenticated RD Gateways are utilized in remote access profiles.
3. Monitor endpoint logs for abnormal process crashes or memory-related errors originating from the `xfreerdp` or associated client executables.
