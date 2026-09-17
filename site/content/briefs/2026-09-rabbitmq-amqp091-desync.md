---
title: Protocol Desynchronization and Frame Injection in RabbitMQ amqp091-go
slug: 2026-09-rabbitmq-amqp091-desync
description: A critical integer overflow vulnerability in the amqp091-go parser causes protocol desynchronization, allowing remote attackers to inject arbitrary AMQP frames into the network stream.
date: "2026-09-17T19:09:40Z"
lastmod: "2026-09-17T19:12:16Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:rabbitmq:amqp091-go:*:*:*:*:*:*:*:*
tags:
  - data-integrity
  - serialization-vulnerability
  - protocol-corruption
  - denial-of-service
  - memory-exhaustion
  - amqp
  - vulnerability
  - credential-exposure
  - information-disclosure
  - injection
vendors:
  - RabbitMQ
products:
  - amqp091-go (< 1.13.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The parser interprets arbitrary offsets within the remaining payload bytes as valid AMQP frame headers, leading to potential Remote Code Execution.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1557
    technique_name: Adversary-in-the-Middle
    evidence: An attacker performing a network-level downgrade attack can intercept a client connection built under a legacy toolchain.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A single malformed frame can reliably crash the client process, resulting in a persistent Denial of Service (DoS) if the client automatically reconnects and receives the same payload.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Because this sensitive data is retained permanently in-memory within an exported field structure, any peripheral code, internal package, reflective logger, dependency, or automated debugging utility with access to the core *Connection object can read and expose the raw credentials.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker who has partial control over directory naming conventions or environmental variables used to specify local infrastructure paths can execute a parameter injection attack.
    confidence_band: high
cves:
  - id: CVE-2026-77411
references:
  - https://github.com/advisories/GHSA-c5pq-fr2g-9jpf
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77411
  - https://github.com/advisories/GHSA-j497-x9hr-x34x
  - https://github.com/advisories/GHSA-33mj-cw25-m34h
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77405
  - https://github.com/advisories/GHSA-4v58-74mf-rjx3
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77412
  - https://github.com/advisories/GHSA-r9c8-gcjp-xfwh
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77410
  - https://github.com/advisories/GHSA-27gv-rfvv-22mv
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77407
  - https://github.com/advisories/GHSA-465g-fh3v-9jw4
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77404
  - https://github.com/advisories/GHSA-xwwf-m8fg-p9q2
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Development
  immediate_actions:
    - action: Upgrade amqp091-go to 1.13.0 or later
      owner: Development
      due: 24h
      evidence: Source states versions < 1.13.0 are vulnerable
  mitigation_plan:
    - priority: immediate
      action: Upgrade amqp091-go to 1.13.0 or later
      owner: Development
      addresses: CVE-2026-77411
      evidence: GHSA-c5pq-fr2g-9jpf
updates:
  - at: "2026-09-17T19:11:30Z"
    level: L1
    summary: added coverage for amqp091-go (< 1.13.0)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-4v58-74mf-rjx3
  - at: "2026-09-17T19:11:37Z"
    level: L1
    summary: added coverage for amqp091-go (< 1.13.0)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-r9c8-gcjp-xfwh
  - at: "2026-09-17T19:11:45Z"
    level: L2
    summary: added coverage for amqp091-go (< 1.13.0)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-27gv-rfvv-22mv
  - at: "2026-09-17T19:12:08Z"
    level: L1
    summary: added coverage for amqp091-go (< 1.13.0)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-465g-fh3v-9jw4
  - at: "2026-09-17T19:12:16Z"
    level: L1
    summary: added coverage for amqp091-go (< 1.13.0)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-xwwf-m8fg-p9q2
---

The amqp091-go library (vulnerable versions prior to 1.13.0) contains a critical vulnerability (CVE-2026-77411) in the readLongstr function used to process AMQP wire-protocol data. When the parser encounters a string length field exceeding the maximum signed 32-bit integer (2^31 - 1), it triggers an improper error-handling condition. Instead of rejecting the malformed packet, the function performs a silent return, indicating a successful read of an empty string while failing to consume the associated bytes from the network buffer.

This failure leaves the unprocessed payload in the TCP stream, causing the parser to become desynchronized from the actual frame boundaries. As subsequent read operations occur, the parser interprets attacker-controlled bytes as valid AMQP frame headers. This alignment shift allows an unauthenticated attacker to inject malicious AMQP frames - such as channel management or message publication commands - leading to potential connection hijacking or remote code execution within the application context.

## Impact

The vulnerability affects any Go-based application utilizing the rabbitmq/amqp091-go library for AMQP communication. Successful exploitation allows for complete bypass of the AMQP protocol state machine, enabling attackers to issue unauthorized commands or extract data processed by the library. This poses a significant risk to messaging infrastructure relying on the library for secure inter-service communication.

## Recommendation

- Upgrade the amqp091-go package to version 1.13.0 or later immediately.
- Audit network traffic logs for oversized string length parameters in AMQP payloads if deep packet inspection (DPI) or custom application-layer logging is available.
- Implement strict input validation at the application firewall level if upgrading is not immediately feasible, specifically targeting AMQP frame structures with anomalous length values.
