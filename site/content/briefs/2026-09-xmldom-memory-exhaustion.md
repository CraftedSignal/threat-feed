---
title: Denial of Service via Quadratic Memory Consumption in xmldom
slug: 2026-09-xmldom-memory-exhaustion
description: The xmldom parser suffers from a quadratic memory complexity flaw during namespace processing, allowing unauthenticated attackers to trigger process OOM crashes using small, crafted XML payloads.
date: "2026-09-08T21:52:54Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:xmldom_project:xmldom:*:*:*:*:*:node.js:*:*
tags:
  - denial-of-service
  - vulnerability
  - xml
products:
  - xmldom (>= 0.1.5, <= 0.6.0)
  - '@xmldom/xmldom (>= 0.7.0, <= 0.8.14)'
  - '@xmldom/xmldom (>= 0.9.0, <= 0.9.11)'
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A small, highly compressible input exhausts the heap... causing OOM-crash the process.
    confidence_band: high
cves:
  - id: CVE-2026-83615
    epss: 0.00351
references:
  - https://github.com/advisories/GHSA-965w-775f-mr7g
  - https://nvd.nist.gov/vuln/detail/CVE-2026-83615
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade affected @xmldom/xmldom and xmldom packages to the latest patched versions.
      owner: IT Operations
      due: 72h
      evidence: Source provides specific vulnerable version ranges and describes the impact as an unauthenticated DoS.
  mitigation_plan:
    - priority: immediate
      action: Enforce strict XML depth limits in application-level input validation to mitigate the O(N^2) memory scaling.
      owner: Application Security
      addresses: CVE-2026-83615
      evidence: The PoC shows that depth (N) directly correlates to peak memory consumption.
---

The xmldom XML parser contains a vulnerability (CVE-2026-83615) stemming from inefficient namespace map handling during the parsing process. When the parser encounters an element that declares a namespace prefix, it performs a full copy of the current in-scope namespace map into a new object and retains this copy on the element while it remains open on the parse stack. 

For deeply nested XML documents where each element declares a unique namespace, this mechanism leads to O(N²) memory consumption at the peak of the parse operation. Because this occurs during the initial parsing phase, it bypasses application-level security controls, such as schema validation or signature verification. An attacker can craft a small, highly compressible XML payload (less than 500 KB) that forces the parser to allocate gigabytes of heap memory, resulting in an unauthenticated denial-of-service (DoS) via OOM (Out-Of-Memory) process termination. This vulnerability affects multiple versions of both the legacy xmldom package and the current @xmldom/xmldom package.

## Impact

Successful exploitation results in a full loss of service for any application utilizing vulnerable versions of xmldom to process attacker-influenced XML. Because the payload is small and highly compressible, it is effective against services that accept compressed XML over transports such as HTTP redirects or POST requests. The flaw is particularly critical for web services and middleware that parse untrusted XML before reaching authorization or authentication logic.

## Recommendation

Prioritize patching all instances of xmldom and @xmldom/xmldom in your environment. Upgrade to versions that implement prototype-based namespace inheritance instead of full map cloning. Due to the nature of this memory exhaustion, traditional pattern-based WAF signatures may struggle to identify the payload; monitor process memory usage (RSS) on application servers for sudden spikes during XML parsing.

- Upgrade `@xmldom/xmldom` to a version newer than 0.8.14 or 0.9.11.
- Upgrade `xmldom` to a version newer than 0.6.0.
- Monitor application server logs for OOM crash events or unexpected restarts coinciding with high-frequency XML parsing.
- If immediate patching is not possible, implement input length and nesting depth validation before passing data to the DOMParser.
