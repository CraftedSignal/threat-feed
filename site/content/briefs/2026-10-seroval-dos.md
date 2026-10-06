---
title: Denial of Service via Unchecked TypedArray Length in Seroval
slug: 2026-10-seroval-dos
description: The Seroval library is vulnerable to unauthenticated memory and CPU exhaustion due to an unchecked TypedArray length property during JSON deserialization, leading to event loop starvation.
date: "2026-10-06T00:45:14Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:seroval:seroval:*:*:*:*:*:node.js:*:*
tags:
  - denial-of-service
  - vulnerability
  - deserialization
products:
  - seroval (<= 1.6.2)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: The length is one integer in the JSON, so a tiny payload can name any allocation size, and it runs synchronously inside fromJSON, starving the event loop instead of just slowing one request.
    confidence_band: high
cves:
  - id: CVE-2026-104845
    cvss: 7.5
    epss: 0.00432
references:
  - https://github.com/advisories/GHSA-jp82-f5mq-hwhp
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104845
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade seroval to a version > 1.6.2.
      owner: Application Security
      due: 24h
      evidence: CVE-2026-104845 advisory recommends version update.
  mitigation_plan:
    - priority: immediate
      action: Implement request size limits at the load balancer or WAF.
      owner: IT Operations
      addresses: CVE-2026-104845
      evidence: Source notes that tiny payloads trigger the vulnerability; rate/size limiting acts as a preventative control.
---

The Seroval library (versions 1.6.2 and earlier) contains a critical vulnerability in the `deserializeTypedArray` and `fromCrossJSON` functions, identified as CVE-2026-104845. The library fails to validate the source node when casting to an `ArrayBuffer`, specifically failing to bound the element count during deserialization. By supplying a specially crafted JSON payload containing a large integer in the `length` property, an attacker can trigger massive synchronous memory allocations. Because this process occurs within the event loop, it causes immediate service-wide resource exhaustion and denial of service. Unlike the `DataView` implementation which properly throws an error, the `TypedArray` handling remains susceptible to this primitive. This vulnerability impacts any service utilizing Seroval to process untrusted JSON inputs.

## Impact

Successful exploitation results in unauthenticated denial of service by starving the application event loop. This leads to high CPU utilization and potential process crashes due to memory exhaustion. The impact is limited to availability; there is no identified risk to confidentiality or integrity. Any application environment utilizing Seroval to deserialize external input is at risk.

## Recommendation

1. Upgrade the Seroval package to a patched version (beyond 1.6.2) immediately upon release by the maintainers.
2. Implement request size limiting at the API gateway or proxy level to prevent the ingestion of excessively large or malicious JSON payloads before they reach the deserialization layer.
3. Validate incoming JSON structure schema-side before passing payloads to the Seroval `fromJSON` or `fromCrossJSON` methods.
4. Monitor server resource metrics (CPU and Heap memory) for sudden, synchronous spikes that correlate with incoming POST requests to identify potential exploitation attempts.
