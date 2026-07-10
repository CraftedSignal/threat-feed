---
title: OpenClaw Unbounded Memory Allocation Vulnerability
slug: 2024-01-openclaw-memory-allocation
description: The openclaw npm package prior to version 2026.3.22 is vulnerable to unbounded memory allocation due to missing size limits when reading remote media HTTP error bodies, potentially leading to denial-of-service.
date: "2024-01-27T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - openclaw
  - memory-allocation
  - denial-of-service
  - npm
vendors:
  - openclaw
products:
  - openclaw
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
references:
  - https://github.com/advisories/GHSA-4qwc-c7g9-4xcw
rules:
  - title: Detect Large HTTP Error Responses
    description: Detects unusually large HTTP error responses, potentially indicating an attempt to exploit the OpenClaw vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - windows
  - title: Detect OpenClaw process creating large files
    description: Detects OpenClaw processes creating large files, which may indicate memory allocation issues leading to disk overflow.
    platform: sigma
    severity: low
    tactics:
      - resource_hijacking
    techniques:
      - T1496
    data_sources:
      - file_event
      - windows
rules_count: 2
---

The `openclaw` npm package, specifically versions prior to 2026.3.22, contains a vulnerability that can lead to unbounded memory allocation. This flaw occurs when the application processes HTTP error responses from remote media servers. Due to the absence of a hard size cap, the application attempts to read the entire error body into memory without limitation. An attacker could exploit this by sending a large error response, causing the `openclaw` application to allocate excessive memory, potentially leading to a denial-of-service condition. The fix, implemented in version 2026.3.22 and later, introduces bounded prefix reads and capped reads to prevent excessive memory usage. This vulnerability was reported by @YLChen-007.

## Attack Chain

1.  An attacker identifies an `openclaw` application using a vulnerable version (< 2026.3.22).
2.  The attacker crafts a malicious HTTP response with an extremely large error body.
3.  The attacker triggers the application to request a media resource from a server they control, causing the malicious HTTP response to be sent to the application.
4.  The `openclaw` application, lacking a size cap, attempts to read the entire error body into memory using the `fetch.ts` component.
5.  Due to the large size of the error body, the application allocates a significant amount of memory.
6.  The unbounded memory allocation continues until system resources are exhausted or a failure occurs.
7.  The application crashes or becomes unresponsive due to memory exhaustion.
8.  The denial-of-service condition impacts the availability of the `openclaw` application.

## Impact

Successful exploitation of this vulnerability can result in a denial-of-service (DoS) condition. An attacker can cause the `openclaw` application to crash or become unresponsive by exhausting available memory. This could impact any service or application relying on the vulnerable `openclaw` package, potentially disrupting operations and affecting user experience. The number of victims depends on the adoption rate of the vulnerable `openclaw` versions.

## Recommendation

*   Upgrade the `openclaw` npm package to version 2026.3.22 or later to incorporate the fix for the unbounded memory allocation vulnerability.
*   Monitor network traffic for unusually large HTTP error responses originating from media servers interacting with `openclaw` applications (see network_connection rule below).
*   Implement resource limits and monitoring on systems running `openclaw` to detect and mitigate excessive memory allocation.
*   Deploy the provided Sigma rules to detect potential exploitation attempts in your environment (see Sigma rules below).
