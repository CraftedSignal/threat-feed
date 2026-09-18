---
title: Denial of Service via Malicious Source Maps in source-map-js
slug: 2026-09-source-map-js-dos
description: A vulnerability in source-map-js versions 1.2.1 and earlier allows unauthenticated attackers to trigger synchronous event loop blocking by supplying malformed indexed source maps containing extreme offset line values.
date: "2026-09-18T20:07:17Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:source-map-js_project:source-map-js:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - web-application
  - supply-chain
cves:
  - id: CVE-2026-93749
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93749
action_plan:
  priority: elevated
  owners:
    - Development
    - IT Operations
  immediate_actions:
    - action: Update source-map-js dependency to a patched version (CVE-2026-93749).
      owner: Development
      due: 48h
      evidence: Source document indicates version <= 1.2.1 is vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Implement strict input validation for source map file sizes and numeric fields.
      owner: Development
      addresses: CVE-2026-93749
      evidence: Lack of validation allows large offset values to block the event loop.
---

The npm package source-map-js, specifically in versions up to and including 1.2.1, contains a vulnerability related to the lack of input validation during the processing of indexed source maps. The library fails to perform proper bounds checking on the per-section offset line values provided within a source map file. 

An attacker can exploit this flaw by submitting a crafted source map containing excessively large numeric values for these offsets. When the application attempts to process this map, the lack of validation causes the Node.js event loop to block synchronously while attempting to handle the malformed data. Because Node.js is single-threaded, this blocking behavior effectively results in a denial-of-service (DoS) condition, preventing the application from processing legitimate concurrent requests. This vulnerability is particularly critical for web applications or build pipelines that process user-supplied source maps or allow dynamic parsing of such files.

## Impact

Successful exploitation results in a persistent denial-of-service condition for the target application by exhausting event loop resources. This impacts developers, build systems, or web applications that rely on source-map-js for parsing indexed source maps. The complexity is low as it requires only the submission of a malicious file, and no specific privileges are required, making it a viable target for automated service disruption.

## Recommendation

Prioritized actions for engineering teams:
- Update the source-map-js dependency to a version beyond 1.2.1 as soon as a patch is available.
- Audit applications utilizing source-map-js to identify instances where the parser processes untrusted or external source map input.
- Implement upstream validation on all uploaded files to reject files exceeding expected size limits or containing anomalous numeric fields before reaching the parser.
- Monitor application performance metrics for prolonged event loop latency or spikes in CPU usage correlated with source map processing requests.
