---
title: Denial of Service via Uncontrolled Recursion in RabbitMQ Java Client
slug: 2026-08-rabbitmq-java-dos
description: The RabbitMQ Java client (amqp-client) contains a pre-authentication vulnerability allowing remote attackers to trigger a StackOverflowError by sending deeply nested AMQP table structures.
date: "2026-08-18T20:59:54Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - VMware
products:
  - amqp-client (<= 5.33.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A malicious AMQP peer can crash the client JVM by sending a deeply nested table structure.
    confidence_band: high
cves:
  - id: CVE-2026-69220
references:
  - https://github.com/advisories/GHSA-93j5-89vc-pph4
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-69220
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development
  immediate_actions:
    - action: Update com.rabbitmq:amqp-client to the patched version identified in the vendor advisory
      owner: Development
      due: 72h
      evidence: Remediation section specifies adding a depth counter and updating the library
  mitigation_plan:
    - priority: immediate
      action: Identify services using amqp-client <= 5.33.0
      owner: IT Operations
      addresses: CVE-2026-69220
      evidence: Affected Packages section
---

The RabbitMQ Java client (com.rabbitmq:amqp-client) is vulnerable to a denial-of-service attack due to improper input validation in its `ValueReader` class. Specifically, the methods `readTable()` and `readArray()` recursively invoke `readFieldValue()` without enforcing any depth constraints. An attacker controlling an AMQP server, or performing a Man-in-the-Middle (MitM) attack, can exploit this by crafting an AMQP frame containing approximately 580 levels of nested tables.

Because the `connection.start` frame is processed before authentication occurs, an unauthenticated remote attacker can crash the client's I/O thread. Given the default JVM stack size, this recursion exceeds the available stack memory, triggering a `StackOverflowError`. This issue affects all versions of the `amqp-client` library up to and including 5.33.0. Defenders should prioritize patching to a version incorporating depth-limited parsing logic.

## Impact

Successful exploitation results in an immediate denial-of-service condition for the affected client application. By forcing a `StackOverflowError` on the primary I/O thread, the attacker effectively disconnects the client from the broker and prevents further communication, requiring a restart of the client process to restore connectivity. This vulnerability impacts any service utilizing the affected Java client library to connect to RabbitMQ brokers.

## Recommendation

* Upgrade the `com.rabbitmq:amqp-client` dependency to a version that implements depth-limiting in the `ValueReader` component to remediate CVE-2026-69220.
* In environments where immediate patching is not possible, implement network-level egress filtering or intrusion detection to block unauthorized AMQP connections to internal services.
* Monitor application logs for unexpected I/O thread crashes and `StackOverflowError` exceptions associated with AMQP connection initialization.
