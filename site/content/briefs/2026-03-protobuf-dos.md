---
title: Protobuf PHP Library Denial of Service Vulnerability
slug: 2026-03-protobuf-dos
description: A denial-of-service vulnerability exists in the Protobuf PHP library due to maliciously crafted messages with negative varints or deep recursion, leading to application crashes and impacting service availability.
date: "2026-03-25T21:04:21Z"
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

A high-severity denial-of-service (DoS) vulnerability has been identified in the Protobuf PHP library, affecting versions prior to 4.33.6. The vulnerability stems from the improper handling of maliciously structured Protocol Buffer messages. Specifically, messages containing negative varints or exhibiting deep recursion can trigger excessive resource consumption during parsing. This can lead to application crashes, thereby disrupting service availability. Patches addressing this vulnerability…
