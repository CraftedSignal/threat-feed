---
title: msgpack5 Truncated map32 Header Denial of Service
slug: 2026-10-msgpack5-range-error
description: An out-of-bounds buffer read in msgpack5 versions prior to 6.1.0 (CVE-2026-107302) triggers an unhandled RangeError when encountering truncated map32 headers, leading to potential application-level denial of service.
date: "2026-10-08T19:26:21Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:msgpack5_project:msgpack5:*:*:*:*:*:node.js:*:*
products:
  - msgpack5 (< 6.1.0)
cves:
  - id: CVE-2026-107302
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-8f34-f56x-9xph
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Engineering
  immediate_actions:
    - action: Upgrade msgpack5 to version 6.1.0 or later
      owner: Engineering
      due: 72h
      evidence: Source explicitly mandates upgrade to 6.1.0 to fix header validation
  mitigation_plan:
    - priority: immediate
      action: Patch msgpack5 to 6.1.0
      owner: Engineering
      addresses: CVE-2026-107302
      evidence: Source identifies 6.1.0 as the version addressing the RangeError flaw
---

The msgpack5 library is susceptible to a denial-of-service vulnerability (CVE-2026-107302) affecting versions prior to 6.1.0. The flaw resides in the decoding logic for 'map32' structures. When the library receives a truncated map32 header (specifically identified by the 0xdf type prefix) that provides fewer than the required five bytes, the internal decoder fails to throw the expected 'IncompleteBufferError'. Instead, the decoder initiates an out-of-bounds buffer read, resulting in a 'RangeError'. This inconsistency disrupts stream and request processing in dependent applications, which typically rely on catching 'IncompleteBufferError' to safely wait for additional data. While the vulnerability does not lead to arbitrary code execution or disclosure of adjacent memory due to underlying buffer implementation checks, it enables a remote attacker to crash specific services or terminate active worker processes by injecting malformed data payloads.

## Impact

The vulnerability affects any application using msgpack5 < 6.1.0 to deserialize message pack data from untrusted network sources. Successful exploitation results in the abrupt termination of application processes or request handlers, causing a denial-of-service condition. This impact is significant for high-throughput messaging or API services that process serialized payloads, as these services are often critical components of distributed architectures.

## Recommendation

- Upgrade the msgpack5 package to version 6.1.0 or later to ensure proper validation of map32 headers.
- Implement upstream validation for input buffers if immediate patching is not possible; ensure at least five bytes are present for payloads starting with the 0xdf prefix.
- Apply defensive coding in application-level error handlers to catch 'RangeError' for logic flows utilizing msgpack5, treating it as an incomplete input signal until the library is patched.
