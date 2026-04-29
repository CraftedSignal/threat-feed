---
title: Protobuf PHP Library Denial of Service Vulnerability
slug: 2026-03-protobuf-dos
description: A denial-of-service vulnerability exists in the Protobuf PHP library due to maliciously crafted messages with negative varints or deep recursion, leading to application crashes and impacting service availability.
date: "2026-03-25T21:04:21Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - protobuf
  - dos
  - php
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-p2gh-cfq4-4wjc
  - https://github.com/protocolbuffers/protobuf/issues/24159
  - https://github.com/protocolbuffers/protobuf/issues/25067
  - https://github.com/protocolbuffers/protobuf/commit/60e93d2
  - https://github.com/protocolbuffers/protobuf/commit/c8e9b27
rules:
  - title: Detect Potential Protobuf DoS Exploitation via HTTP Request Size
    description: Detects unusually large HTTP requests that might be indicative of an attempt to exploit the Protobuf DoS vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
  - title: Detect Excessive Server Response Time Associated with Protobuf Processing
    description: Monitors server response times for prolonged delays, potentially indicating resource exhaustion during Protobuf parsing.
    platform: sigma
    severity: low
    tactics:
      - impact
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A high-severity denial-of-service (DoS) vulnerability has been identified in the Protobuf PHP library, affecting versions prior to 4.33.6. The vulnerability stems from the improper handling of maliciously structured Protocol Buffer messages. Specifically, messages containing negative varints or exhibiting deep recursion can trigger excessive resource consumption during parsing. This can lead to application crashes, thereby disrupting service availability. Patches addressing this vulnerability have been released in versions 5.34.0-RC1 and 4.33.6 of the Protobuf library. Defenders should prioritize updating vulnerable systems to these patched versions to mitigate potential exploitation.

## Attack Chain

1. An attacker crafts a malicious Protocol Buffer message.
2. The message contains either negative varints or exploits deep recursion.
3. The attacker sends the malicious message to a PHP application using the vulnerable Protobuf library.
4. The PHP application attempts to parse the malicious message using the affected Protobuf library.
5. During parsing, the negative varints or deep recursion trigger excessive resource consumption, such as CPU or memory.
6. The application becomes unresponsive due to resource exhaustion.
7. The application crashes, leading to a denial of service.

## Impact

Successful exploitation of this vulnerability results in a denial-of-service condition, rendering affected applications unavailable. This can impact any service relying on the Protobuf PHP library to process untrusted data, such as APIs, message queues, or data storage systems. The number of affected services depends on the prevalence of the vulnerable Protobuf library within an organization's infrastructure. This issue can lead to significant disruption and potential data loss or corruption if applications crash while processing critical data.

## Recommendation

*   Upgrade the `composer/google/protobuf` package to version 4.33.6 or later to remediate the vulnerability.
*   Monitor web server logs for anomalous request patterns indicative of exploitation attempts targeting Protobuf message processing (webserver log source).
*   Implement rate limiting and input validation on services that process Protocol Buffer messages to mitigate the impact of malicious inputs (webserver log source).
