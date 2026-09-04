---
title: Memory Exhaustion in amqp091-go Client via Oversized AMQP Frames
slug: 2026-09-amqp-mem-exhaustion
description: The amqp091-go library fails to enforce negotiated frame size limits, allowing a malicious AMQP broker to trigger arbitrary memory allocation and application-layer denial of service via CVE-2026-79921.
date: "2026-09-04T00:06:54Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:rabbitmq:amqp091-go:*:*:*:*:*:*:*:*
vendors:
  - RabbitMQ
products:
  - amqp091-go (< 1.13.0)
cves:
  - id: CVE-2026-79921
    epss: 0.00316
references:
  - https://github.com/advisories/GHSA-6c5v-hqjr-5xxp
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade amqp091-go dependency to 1.13.0 or later
      owner: Application Security
      due: 72h
      evidence: Source states vulnerable version is < 1.13.0
  mitigation_plan:
    - priority: immediate
      action: Upgrade package version to 1.13.0
      owner: IT Operations
      addresses: CVE-2026-79921
      evidence: Source states vulnerable version is < 1.13.0
---

The amqp091-go library (versions prior to 1.13.0) contains a vulnerability (CVE-2026-79921) related to improper input validation during the processing of AMQP 0-9-1 frames. During the initial connection handshake, both the client and broker negotiate a maximum frame size (frame_max) to govern data transfer parameters. 

Researchers identified that the library fails to enforce this established constraint when receiving content body frames. If a malicious or compromised broker transmits a frame header declaring a payload size that exceeds the agreed-upon frame_max, the library trustfully accepts the value. This results in the client performing memory allocations dictated by the broker rather than the negotiated protocol limits. An attacker acting as a rogue broker can exploit this behavior by sending frames with excessively large declared sizes, leading to significant memory exhaustion and potential Out-Of-Memory (OOM) application crashes. This vulnerability represents a failure of the client to adhere to the security constraints defined by the AMQP 0-9-1 specification.

## Impact

Successful exploitation leads to an application-layer Denial of Service (DoS) against any service or client utilizing the amqp091-go library to connect to an untrusted or compromised AMQP broker. This can result in service instability, application crashes, and potential disruption of dependent message-processing workflows.

## Recommendation

- Upgrade the amqp091-go library to version 1.13.0 or later immediately to incorporate proper frame size validation.
- Review connection configurations to ensure that clients are only interacting with trusted or hardened AMQP broker infrastructure.
- Monitor application memory metrics and infrastructure logs for anomalous growth or OOM events associated with the Go service binary.
