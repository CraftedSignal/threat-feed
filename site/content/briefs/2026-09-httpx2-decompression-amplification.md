---
title: HTTPX2 Decompression Amplification Vulnerability (CVE-2026-84382)
slug: 2026-09-httpx2-decompression-amplification
description: The HTTPX2 library, prior to version 2.12.0, is vulnerable to a decompression amplification attack where malicious compressed HTTP responses can trigger large, unbonded memory allocations, leading to denial-of-service via memory exhaustion.
date: "2026-09-08T21:53:14Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:httpx2:httpx2:*:*:*:*:*:python:*:*
tags:
  - denial-of-service
  - vulnerability
  - memory-exhaustion
vendors:
  - HTTPX2
products:
  - httpx2 (< 2.12.0)
cves:
  - id: CVE-2026-84382
    cvss: 7.5
    epss: 0.0035
references:
  - https://github.com/advisories/GHSA-8xx6-hgc6-gc2m
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84382
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade all instances of httpx2 to version 2.12.0 or later
      owner: IT Operations
      due: 48h
      evidence: Mitigation section of the GHSA advisory
  mitigation_plan:
    - priority: immediate
      action: Patch httpx2 to 2.12.0 or later
      owner: Application Security
      addresses: CVE-2026-84382
      evidence: Source advisory recommends version 2.12.0 or later
---

The HTTPX2 Python library, used for making HTTP requests, contains a vulnerability (CVE-2026-84382) involving how it processes compressed response bodies. Prior to version 2.12.0, the library's default transport mechanism fully decompressed each incoming network read chunk (up to 64 KiB) into an intermediate memory buffer before yielding the data to the consuming application. 

Because of this lack of bounded memory allocation during decompression, an attacker controlling a remote server can provide a highly compressed payload using algorithms like Gzip, Deflate, Brotli, or Zstd. At the maximum compression ratio for DEFLATE, which is approximately 1032:1, a 64 KiB chunk can expand into roughly 64 MiB of memory in a single allocation. Even if the application logic intends to stream data to keep memory usage low, these transient, uncontrolled allocations occur during the underlying decompression phase. This behavior exposes applications that interact with untrusted third-party servers to memory pressure or total service failure via out-of-memory (OOM) termination.

## Impact

Applications that fetch resources from untrusted or attacker-influenced origins are at significant risk. This includes webhook receivers, link unfurlers, web crawlers, SSRF-prone services, and automated tools that follow HTTP redirects. Exploitation requires no authentication or user interaction beyond triggering the application to perform an HTTP request to the attacker-controlled server. Successful exploitation results in process crashes or severe performance degradation due to memory exhaustion, effectively causing a denial-of-service.

## Recommendation

Prioritize the upgrade of the HTTPX2 library to version 2.12.0 or later across all applications that perform egress HTTP requests to untrusted endpoints. Version 2.12.0 introduces bounded, incremental decompression buffers to prevent uncontrolled memory spikes. Audit internal infrastructure to identify services leveraging HTTPX2 for fetching external resources, particularly in SSRF-sensitive environments, and ensure dependencies are updated via package management tools.
