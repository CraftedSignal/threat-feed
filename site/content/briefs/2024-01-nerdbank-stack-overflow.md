---
title: Nerdbank.MessagePack DateTime Decoding Stack Overflow Vulnerability
slug: 2024-01-nerdbank-stack-overflow
description: A malicious MessagePack payload can trigger a StackOverflowException in Nerdbank.MessagePack due to an uncontrolled stack allocation when decoding DateTime values with oversized timestamp extension lengths, leading to process termination.
date: "2024-01-26T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - denial-of-service
  - stack-overflow
  - messagepack
vendors:
  - NuGet
products:
  - Nerdbank.MessagePack (< 1.1.62)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-2cwq-pwfr-wcw3
  - https://cwe.mitre.org/data/definitions/789.html
  - https://github.com/msgpack/msgpack/blob/master/spec.md#timestamp-extension-type
rules:
  - title: Nerdbank MessagePack Suspicious Stack Allocation
    description: Detects potential attempts to exploit the Nerdbank.MessagePack stack overflow vulnerability by identifying processes deserializing MessagePack data with unusually large extension sizes.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.002
    data_sources:
      - process_creation
      - windows
  - title: Nerdbank MessagePack Suspicious DateTime Deserialization
    description: Detects potential attempts to trigger the Nerdbank.MessagePack stack overflow during DateTime deserialization from untrusted sources.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Nerdbank.MessagePack versions prior to 1.1.62 are vulnerable to an uncontrolled stack allocation vulnerability. This flaw allows an attacker to craft a malicious MessagePack payload that declares an oversized timestamp extension length. When the application attempts to deserialize this payload and encounters a `DateTime` value, the reader allocates an attacker-controlled number of bytes on the stack. This excessive allocation results in a `StackOverflowException`, causing the application to terminate. This vulnerability impacts applications that deserialize MessagePack data from untrusted sources and can lead to denial-of-service conditions. Defenders should prioritize patching or implementing workarounds to mitigate this risk.

## Attack Chain

1.  Attacker crafts a malicious MessagePack payload with an invalid timestamp extension length (not 4, 8, or 12 bytes).
2.  The target application receives the malicious MessagePack payload from an untrusted source.
3.  The application attempts to deserialize the MessagePack data using Nerdbank.MessagePack.
4.  During deserialization, the `DateTime` decoder encounters the malicious timestamp extension.
5.  The decoder derives `tokenSize` from the attacker-controlled extension length *before* validating its size.
6.  The unvalidated size is used in a `stackalloc` on the streaming reader's slow path, allocating an excessive amount of stack memory.
7.  The excessive stack allocation triggers a `StackOverflowException`.
8.  The `StackOverflowException` terminates the application process, resulting in a denial of service.

## Impact

Successful exploitation of this vulnerability leads to a denial-of-service condition due to process termination. The vulnerability affects applications deserializing MessagePack data from untrusted sources, particularly those handling long-running processes such as services, APIs, workers, or message consumers. Even small malicious payloads can trigger the vulnerability due to the attacker-controlled extension length. This could potentially disrupt critical business functions relying on affected applications.

## Recommendation

*   Upgrade to Nerdbank.MessagePack version 1.1.62 or later to remediate the vulnerability.
*   Implement pre-validation of MessagePack extension headers, rejecting timestamp extensions with lengths other than 4, 8, or 12 bytes, as suggested in the advisory [GHSA-2cwq-pwfr-wcw3].
*   Deploy the Sigma rule "Nerdbank MessagePack Suspicious Stack Allocation" to detect potential exploitation attempts in your environment.
*   If immediate patching is not feasible, consider running deserialization of untrusted payloads in isolated processes that can be safely restarted, as described in [GHSA-2cwq-pwfr-wcw3].
