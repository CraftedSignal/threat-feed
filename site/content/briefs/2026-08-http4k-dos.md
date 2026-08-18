---
title: Unbounded Gzip Decompression Denial of Service in http4k
slug: 2026-08-http4k-dos
description: The http4k library fails to limit the size of decompressed gzip data, allowing unauthenticated remote attackers to trigger JVM heap exhaustion via small, highly compressed payloads.
date: "2026-08-18T00:46:52Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - denial-of-service
  - vulnerability
  - web-server
vendors:
  - http4k
products:
  - http4k-core
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A small malicious gzip-encoded request body (on the order of kilobytes) could decompress to gigabytes, exhausting the JVM heap and denying service to other clients.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-g4w2-6h2r-3m3w
  - https://cwe.mitre.org/data/definitions/409.html
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Audit dependency tree for vulnerable http4k-core versions
      owner: IT Operations
      due: 24h
      evidence: Affected versions identified in security advisory
  mitigation_plan:
    - priority: immediate
      action: Upgrade http4k-core to patched versions 4.51.0.0, 5.42.0.0, or 6.49.0.0
      owner: IT Operations
      addresses: CVE-2026-53659
      evidence: Vendor release notes confirm fix implementation
---

The http4k library (http4k-core) contains a vulnerability in its `ServerFilters.GZip` and `RequestFilters.GunZip` components, where incoming request bodies are decompressed without verifying the final, expanded size. This flaw, tracked as CVE-2026-53659, allows an attacker to send a maliciously crafted, highly compressed gzip request of only a few kilobytes. Upon processing, the request expands significantly within the JVM heap, leading to memory exhaustion and a complete denial-of-service for the affected server.

This vulnerability has existed since 2017 and affects multiple versions across the v4, v5, and v6 branches. Because the library is widely used for building HTTP services, this poses a high risk to applications that expose endpoints accepting compressed inputs. Defenders must prioritize upgrading to the patched versions or implementing protective measures at the network edge to inspect or reject oversized request payloads.

## Impact

Successful exploitation results in service unavailability due to JVM OutOfMemory errors. Any application using the affected http4k filters to process incoming requests is susceptible to unauthenticated remote exploitation. Impact is restricted to availability (DoS); there is no evidence of remote code execution or data exfiltration associated with this vulnerability.

## Recommendation

- Upgrade `http4k-core` to the patched versions: 4.51.0.0, 5.42.0.0, or 6.49.0.0 immediately to apply the default 10MB decompression limit.
- Implement request body size limits at the edge (Load Balancer, Reverse Proxy, or WAF) to drop excessively large or potentially malicious compressed requests before they reach the application layer.
- For legacy applications that cannot be updated, implement a custom filter in the http4k pipeline that restricts the size of the `InputStream` before decompression occurs.
