---
title: RabbitMQ Java Client Out-of-Memory Vulnerability via Frame Negotiation
slug: 2026-09-rabbitmq-frame-oom
description: A logic error in the RabbitMQ Java client's frame size negotiation allows a malicious server to trigger a massive memory allocation and service crash by exploiting an integer comparison flaw in frame handling.
date: "2026-09-17T19:14:52Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:rabbitmq:amqp-client:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - denial-of-service
  - java
  - rabbitmq
vendors:
  - RabbitMQ
products:
  - amqp-client (< 5.34.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A single malicious frame triggers up to ~2GB allocation (Integer.MAX_VALUE bytes) causing OOM crash.
    confidence_band: high
cves:
  - id: CVE-2026-75516
references:
  - https://github.com/advisories/GHSA-jh4v-gfqj-7rhx
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75516
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade com.rabbitmq:amqp-client to 5.34.0 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-75516 resolution in upstream advisory
  mitigation_plan:
    - priority: immediate
      action: Patch library dependency
      owner: Application Security
      addresses: CVE-2026-75516
      evidence: Source advisory recommends version 5.34.0
---

The RabbitMQ Java client library (com.rabbitmq:amqp-client) is vulnerable to an Out-Of-Memory (OOM) denial-of-service condition due to a logic flaw in how it negotiates the maximum frame size (`frameMax`) with an AMQP server. When an AMQP server or an adversary in a Man-in-the-Middle (MITM) position sends a `Connection.Tune` handshake with `frameMax=0` (signifying unlimited size per the AMQP specification), the client incorrectly executes `Math.min(maxInboundMessageBodySize, 0)`. This operation results in a value of zero, which the internal `Utils.framePayloadLimit` function interprets as a request for `Integer.MAX_VALUE`. Consequently, the client's existing frame size protections are bypassed, and a single crafted frame with a large size field forces the JVM to attempt an allocation of approximately 2GB, causing the process to crash. This affects all clients using versions prior to 5.34.0.

## Attack Chain

1. Attacker initiates a connection to the RabbitMQ Java client as a malicious AMQP server.
2. The client initiates the standard AMQP `Connection.Tune` handshake negotiation.
3. The attacker sends a `Connection.Tune` response with the `frameMax` field set to 0.
4. The client's `AMQConnection` logic incorrectly evaluates the limit as 0 instead of falling back to the configured `maxInboundMessageBodySize`.
5. The client sets the effective frame payload limit to `Integer.MAX_VALUE` due to the misinterpretation of 0-means-unlimited.
6. The attacker sends a frame (method, header, or body) with a manipulated size field set to a very large value (e.g., 0x1FFFFFFF).
7. The client executes `new byte[frameSize]` inside `Frame.readFrom()` based on the attacker's supplied size.
8. The JVM exhausts available heap memory, resulting in an OOM crash and denial of service for the client application.

## Impact

Successful exploitation results in an immediate denial-of-service (DoS) condition on any application using the vulnerable RabbitMQ Java client. Because the crash occurs during frame processing, it is highly effective against any client connecting to a compromised or malicious AMQP broker. This impacts all sectors relying on RabbitMQ for messaging, particularly in Java-based microservices architectures where a single crashed node can disrupt downstream message processing.

## Recommendation

Update the `com.rabbitmq:amqp-client` library to version 5.34.0 or later immediately to incorporate the corrected logic for `frameMax` negotiation. If patching is not immediately feasible, ensure that connections are only established to trusted brokers and inspect outbound traffic for anomalous `Connection.Tune` frames.
