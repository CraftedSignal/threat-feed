---
brief_id: brief-2026-10-28-jackson-dataformat-protobuf-integer-overflow
event_id: brief-2026-10-28-jackson-dataformat-protobuf-integer-overflow
revision: 1
activity_at: "2026-10-28T01:35:47Z"
title: 'FasterXML jackson-dataformat-protobuf: Signed integer overflow denial-of-service (CVE-2026-104016)'
slug: 2026-10-jackson-dataformat-protobuf-integer-overflow
description: A signed integer overflow in the ProtobufParser component of jackson-dataformat-protobuf (CVE-2026-104016) allows unauthenticated remote attackers to trigger an OutOfMemoryError and crash Java applications by providing a maliciously crafted length-prefixed field.
date: "2026-10-28T01:35:47Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:fasterxml:jackson-dataformat-protobuf:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - java
  - deserialization
vendors:
  - FasterXML
products:
  - jackson-dataformat-protobuf
cves:
  - id: CVE-2026-104016
    cvss: 7.5
    kev_status: "false"
references:
  - https://github.com/FasterXML/jackson-dataformats-binary/security/advisories/GHSA-c2rq-mcfv-jw29
  - https://sploitus.com/exploit?id=CVE-2026-104016
  - https://sploitus.com/exploit?id=CVE-2026-104016&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Inventory all applications using jackson-dataformat-protobuf and apply vendor patches
      owner: Application Security
      due: 48h
      evidence: Source advisory GHSA-c2rq-mcfv-jw29
  hunt_leads:
    - lead: Search application logs for Java stack traces containing 'OutOfMemoryError' and 'ProtobufParser'
      technique_id: T1499
      data_needed:
        - Application log files
        - JVM stderr logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Source describes error as an OutOfMemoryError in ProtobufParser
  mitigation_plan:
    - priority: immediate
      action: Deploy network-level filtering to block malformed Protobuf traffic if immediate patching is not feasible
      owner: Network Security
      addresses: CVE-2026-104016
      evidence: Exploitation requires submitting crafted length-prefixed data
  gaps:
    - Need to verify versioning information against the GitHub Security Advisory
---

A signed integer overflow vulnerability in `jackson-dataformat-protobuf` (CVE-2026-104016) allows attackers to crash services via an `OutOfMemoryError`. The vulnerability exists because `ProtobufParser` utilizes 32-bit signed integer arithmetic for bounds checking when parsing length-prefixed strings. By providing a varint-encoded length near `Integer.MAX_VALUE`, an attacker can cause an overflow during pointer calculation, bypassing bounds checks and triggering an unrestrained memory allocation in `TextBuffer.expandCurrentSegment`.

This vulnerability is significant because existing configuration-based protections, such as `StreamReadConstraints` (e.g., `maxStringLength`, `maxDocumentLength`), fail to gate this specific code path. Furthermore, the JVM rejects the resulting massive array allocation before application-level heap constraints are evaluated, making `-Xmx` heap tuning ineffective as a mitigation.

## Impact
Successful exploitation results in an immediate service disruption via `OutOfMemoryError`, effectively achieving a denial-of-service (DoS) against any Java service processing untrusted Protobuf data using affected versions of the library.

## Recommendation
- Identify all Java applications utilizing `jackson-dataformat-protobuf` in the dependency tree.
- Prioritize updating to the patched version of `jackson-dataformat-protobuf` as identified in the upstream GitHub advisory (GHSA-c2rq-mcfv-jw29).
- Implement request size limits at the network edge or WAF layer to prevent processing of excessively large, malformed Protobuf messages if patching is delayed.
- Monitor application logs for frequent `OutOfMemoryError` events associated with deserialization processes.
