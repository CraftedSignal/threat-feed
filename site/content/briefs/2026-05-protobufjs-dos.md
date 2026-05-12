---
title: protobuf.js Denial-of-Service Vulnerability via Unbounded Recursion (CVE-2026-44289)
slug: 2026-05-protobufjs-dos
description: protobuf.js is vulnerable to a denial-of-service (DoS) attack (CVE-2026-44289) due to unbounded recursion while decoding nested protobuf data, potentially leading to stack exhaustion and process crashes when processing crafted protobuf binary payloads.
date: "2026-05-12T15:05:31Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - denial of service
  - protobufjs
  - CVE-2026-44289
vendors:
  - npm
products:
  - protobufjs (<= 7.5.5)
  - protobufjs (>= 8.0.0, <= 8.0.1)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-685m-2w69-288q
  - CVE-2026-44289
rules:
  - title: Detect protobuf.js Excessive Recursion Attempt
    description: Detects a potential denial-of-service attack by monitoring for excessive recursion depth in processes using protobuf.js.
    platform: sigma
    severity: medium
    tactics:
      - cve-2026-44289
      - impact
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - windows
  - title: Detect protobuf.js Out-of-Memory Exception
    description: Detects an out-of-memory (OOM) exception associated with protobuf.js, which might be a sign of the DoS vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - cve-2026-44289
      - impact
    techniques:
      - T1499.004
    data_sources:
      - application
      - windows
rules_count: 2
---

protobuf.js versions 7.5.5 and earlier, and 8.0.0 through 8.0.1, are susceptible to a denial-of-service vulnerability (CVE-2026-44289) due to unbounded recursion during the decoding of nested protobuf data. This vulnerability is triggered when the decoder encounters deeply nested structures, either through unknown group fields or nested message fields. An attacker can exploit this by crafting a malicious protobuf binary payload that, when processed by an application using a vulnerable version of protobuf.js, causes the JavaScript call stack to be exhausted. This stack exhaustion leads to a process crash or decoding failure due to a stack overflow. This vulnerability poses a risk to applications that decode untrusted protobuf binary input, potentially disrupting service availability and requiring process restarts.

## Attack Chain

1.  The attacker crafts a malicious protobuf binary payload. This payload contains excessively nested protobuf structures.
2.  The application receives the crafted protobuf binary payload as input. This input may originate from a network request, file upload, or other data source.
3.  The application uses a vulnerable version of protobuf.js (<= 7.5.5 or >= 8.0.0 and <= 8.0.1) to decode the protobuf binary data.
4.  During decoding, the protobuf.js library recursively processes the nested structures within the payload.
5.  Due to the excessive nesting, the JavaScript call stack grows without bound. The recursion occurs when either skipping unknown group fields or decoding nested message fields.
6.  The JavaScript call stack reaches its limit, resulting in a stack overflow error.
7.  The application process terminates abruptly due to the unhandled exception.
8.  The application becomes unavailable, leading to a denial-of-service condition.

## Impact

Successful exploitation of this vulnerability (CVE-2026-44289) leads to a denial-of-service condition, where the application processing the crafted protobuf data crashes or becomes unresponsive. The impact depends on the role of the affected application; a crash in a critical service can disrupt operations, while a crash in a less critical component may only cause temporary inconvenience. The number of affected applications depends on the adoption of vulnerable protobuf.js versions and the prevalence of untrusted protobuf data processing. The attack can cause loss of service availability and potential data integrity issues if decoding is interrupted mid-process.

## Recommendation

*   Upgrade protobuf.js to the latest version to patch CVE-2026-44289.
*   If upgrading is not immediately feasible, implement input validation to reject excessively nested protobuf messages at the application layer.
*   Consider isolating protobuf decoding within a sandboxed process that can be safely restarted to mitigate the impact of crashes.
*   Deploy the Sigma rule "Detect protobuf.js Excessive Recursion Attempt" to identify potential exploitation attempts by monitoring process resource consumption.
