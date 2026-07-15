---
title: Pomerium Pre-Auth Memory Exhaustion via Unbounded zstd Decompression
slug: 2026-07-pomerium-dos
description: Pomerium proxy deployments using the stateless authentication flow (Pomerium Zero or hosted authenticate) are vulnerable to a pre-authentication memory exhaustion denial of service, allowing an unauthenticated attacker to send specially crafted HPKE-encrypted zstd payloads to the `/.pomerium/callback` endpoint, leading to excessive memory allocation and potential proxy crashes.
date: "2026-07-15T23:08:59Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - network
  - vulnerability
  - go
vendors:
  - Pomerium
products:
  - Pomerium (>= 0.32.6, < 0.32.8)
  - Pomerium Zero
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Denial of Service
    technique_id: T1499
    technique_name: Application Layer Denial of Service
    evidence: An attacker who can reach the proxy can allocate hundreds of megabytes of server memory per HTTP request by sending a ~20–40 KB payload.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-ggw3-5987-rx77
iocs:
  - type: domain
    value: authenticate.pomerium.app
ioc_counts:
  domain: 1
---

Pomerium deployments configured for stateless authentication flows (Pomerium Zero or hosted `authenticate.pomerium.app`) are susceptible to a pre-authentication denial of service (DoS) due to unbounded zstd decompression, tracked as CVE-2026-50285. An attacker can leverage the publicly available HPKE receiver public key to craft a malicious payload that, when delivered to the `/.pomerium/callback` endpoint, causes the Pomerium proxy to allocate excessive amounts of memory. This vulnerability in `pkg/hpke/url.go` allows a small (~20-40 KB) compressed input to expand into hundreds of megabytes of uncompressed data, exhausting proxy resources before sender identity validation can occur. This issue impacts Pomerium versions 0.32.6 up to, but not including, 0.32.8 and presents a significant availability risk to organizations relying on Pomerium for application access control.

## Attack Chain

1. An unauthenticated attacker identifies a Pomerium proxy deployment utilizing the stateless authentication flow.
2. The attacker retrieves the Pomerium proxy's public HPKE receiver key by sending an HTTP GET request to the publicly accessible `/.well-known/pomerium/hpke-public-key` endpoint.
3. The attacker generates their own ephemeral HPKE sender key pair to encrypt the malicious payload.
4. The attacker crafts a zstd "decompression bomb" payload, designed to be small when compressed but expand into a very large amount of data upon decompression (e.g., 19 KB compressed to 128 MiB uncompressed).
5. The attacker uses their generated sender private key and Pomerium's retrieved receiver public key to encrypt (seal) the decompression bomb payload.
6. The attacker sends an HTTP GET request to the pre-authenticated `/.pomerium/callback` endpoint on the Pomerium proxy, including the encrypted decompression bomb as a query parameter (e.g., `q`).
7. The Pomerium proxy receives the request and, before validating the sender's identity, proceeds to decrypt and decompress the payload using `hpke.DecryptURLValues` and `decodeQueryStringV2`.
8. Due to the lack of an output size limit in `decodeQueryStringV2`, the decompression of the malicious payload consumes a disproportionate amount of server memory, leading to process degradation, unresponsiveness, or a crash, resulting in a denial of service.

## Impact

This vulnerability enables a pre-authentication denial of service (DoS) against any Pomerium proxy using the hosted/stateless authenticate flow (Pomerium Zero or `authenticate.pomerium.app`). An attacker with network reachability to the proxy's HTTPS port can allocate hundreds of megabytes of server memory per HTTP request by sending a small (approximately 20 - 40 KB) malicious payload. Sustained attacks with concurrent requests can quickly exhaust available memory, leading to the crash of the proxy process and effectively blocking all user access to every application protected by that Pomerium deployment. No credentials, session cookies, or insider access are required for this attack.

## Recommendation

* Upgrade Pomerium to version 0.32.8 or later immediately to address CVE-2026-50285.
* Monitor the memory usage of Pomerium proxy processes for sudden spikes or sustained high consumption, which could indicate a decompression bomb attack.
* If immediate patching is not possible, consider implementing network-level rate limiting or Web Application Firewall (WAF) rules to restrict repeated requests to the `/.pomerium/callback` endpoint from suspicious IP addresses, referencing the IOCs.
