---
title: Wire Protobuf Negative Length Vulnerability (CVE-2026-45799)
slug: 2026-05-wire-negative-length-protobuf
description: A vulnerability in Wire's protobuf group-skipping logic allows a crafted payload with a negative length to cause a runtime exception and potentially crash services decoding untrusted protobuf, addressed in version 6.3.0.
date: "2026-05-19T19:55:35Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - protobuf
  - denial-of-service
  - CVE-2026-45799
  - wire
vendors:
  - Square
products:
  - wire-runtime
  - wire-runtime-jvm
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499.004
    technique_name: 'Endpoint Denial of Service: Resource Exhaustion'
references:
  - https://github.com/advisories/GHSA-7xpr-hc2w-34m9
  - CVE-2026-45799
rules:
  - title: Detect Wire Protobuf Negative Length Exploitation Attempt
    description: Detects CVE-2026-45799 exploitation attempt — crafted protobuf payload with negative length leading to ArrayIndexOutOfBoundsException in Wire library.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Wire Protobuf Negative Length Exploitation Attempt - Exception
    description: Detects CVE-2026-45799 exploitation — monitors for the specific ArrayIndexOutOfBoundsException thrown by vulnerable Wire versions.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499.004
    data_sources:
      - application
      - java
rules_count: 2
---

A vulnerability exists in Square's Wire protobuf library where the group-skipping logic does not reject negative lengths before skipping a length-delimited field inside a group. This issue, identified as CVE-2026-45799, allows an attacker to craft a malicious protobuf payload that causes Wire to throw an unchecked runtime exception (ArrayIndexOutOfBoundsException) during decoding, instead of the expected IOException. This can crash services that decode untrusted protobuf payloads while only handling Wire's documented checked decoding failures. The vulnerability affects `wire-runtime` versions before 6.3.0, `wire-runtime-jvm` legacy releases including 5.3.1 and 5.3.3, and Wire 7 alpha releases prior to the fix being merged. The fix is implemented in Wire version 6.3.0, released by Square.

## Attack Chain

1. An attacker crafts a protobuf payload with a START_GROUP field (wire type 3) containing a LENGTH_DELIMITED field inside the group.
2. The LENGTH_DELIMITED field is assigned a negative length value (e.g., -128) by encoding it as a signed Int varint (e.g., `0x80 0xFF 0xFF 0xFF 0x0F`).
3. The `ByteArrayProtoReader32.skipGroup()` or `ProtoReader.skipGroup()` function in Wire is called to skip the unknown group.
4. The `internalReadVarint32()` function reads the length as a signed Int but does not validate if it's non-negative.
5. The `skip(length)` function is then called without a check for a negative length, leading to `pos + byteCount` being negative.
6. The `pos` counter in the `ByteArrayProtoReader32` underflows to an invalid negative position (e.g., -121).
7. The next `readByte()` call attempts to access the source array with the negative position, resulting in an `ArrayIndexOutOfBoundsException`.
8. This exception is a `RuntimeException` that escapes Wire's documented `IOException` boundary, potentially crashing the service.

## Impact

The vulnerability can lead to a denial-of-service (DoS) condition in services that decode untrusted protobuf payloads using vulnerable versions of the Wire library. Attackers can send specially crafted payloads to crash affected services. This can impact availability and potentially disrupt business operations. Legacy versions using `com.squareup.wire:wire-runtime-jvm` including `5.3.1` and `5.3.3` are vulnerable and will not receive patches. Services using vulnerable versions of `com.squareup.wire:wire-runtime` prior to `6.3.0`, or affected alpha releases of Wire 7, are also at risk.

## Recommendation

*   Upgrade to `com.squareup.wire:wire-runtime:6.3.0` or later to address CVE-2026-45799.
*   Migrate from the discontinued `com.squareup.wire:wire-runtime-jvm` artifact to `com.squareup.wire:wire-runtime:6.3.0` or later.
*   Until the next Wire 7 alpha release is available, avoid decoding untrusted protobuf payloads with affected alpha versions or build from a commit containing the fix.
*   Deploy the "Detect Wire Protobuf Negative Length Exploitation Attempt" Sigma rule to identify attempts to exploit CVE-2026-45799.
