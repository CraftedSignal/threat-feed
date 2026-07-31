---
title: Detection of Malicious AMQP Multi-Queue Message Purging
slug: 2026-07-amqp-queue-purge
description: Adversaries may perform rapid multi-queue purges in AMQP-based messaging systems, such as RabbitMQ, to facilitate data destruction or cause widespread application disruption following credential compromise.
date: "2026-07-31T15:23:55Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - RabbitMQ
products:
  - RabbitMQ
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: The AMQP queue.purge method removes all messages from a queue that are not awaiting acknowledgment.
    confidence_band: high
references:
  - https://www.rabbitmq.com/amqp-0-9-1-reference
  - https://attack.mitre.org/techniques/T1485/
---

This threat brief focuses on the detection of destructive message-clearing operations within AMQP-based messaging infrastructure. An adversary who successfully gains unauthorized access to a message broker (e.g., RabbitMQ) can leverage the `queue.purge` method to permanently remove all ready messages from targeted queues. While administrative maintenance can involve purging queues, malicious actors often perform these operations in rapid bursts to disrupt application services, destroy data, or hinder incident response efforts. Defenders should prioritize visibility into cleartext AMQP traffic to monitor for sequential purge commands originating from a single source. This detection mechanism specifically identifies instances where a single client-to-broker connection purges at least three distinct queues within a nine-minute window, effectively filtering out isolated operational events while highlighting potentially harmful bulk destruction.

## Attack Chain

1. An attacker obtains valid credentials for an AMQP-based message broker, such as RabbitMQ, through credential dumping or phishing.
2. The attacker establishes a network connection to the target broker as an authenticated client.
3. The attacker identifies high-value queues containing critical business data or task instructions.
4. The attacker issues a series of AMQP `queue.purge` method calls across multiple distinct queues to maximize operational impact.
5. The broker processes the purge requests and returns `queue.purge-ok` status messages for each successful operation.
6. The attacker repeats this process until the targeted application services become unavailable or the message queue backlog is entirely cleared.
7. Final objective is achieved: mass data destruction and denial of service for dependent microservices.

## Impact

Successful exploitation of this technique leads to the permanent loss of non-acknowledged messages, resulting in application downtime, system failure, or the loss of sensitive data waiting for processing. Targeted sectors include any organization relying on RabbitMQ for distributed architecture or asynchronous message processing, particularly in financial, logistics, and cloud-native environments. If successful, the attack results in immediate disruption of downstream consumer applications and can severely complicate disaster recovery efforts.

## Recommendation

- Implement network traffic monitoring to capture and inspect AMQP 0.9.1 protocol metadata, specifically focusing on the `queue.purge` method.
- Review RabbitMQ audit logs to correlate client connection IPs with authenticated user accounts to identify the source of the purge burst.
- Deploy the provided logic to detect and alert on high-cardinality queue purges from single clients to differentiate malicious destruction from routine maintenance.
- Restrict queue management and configuration permissions to the minimum set required by application service accounts.
- Establish alerting for unusual consumer behavior and sudden drops in queue depth metrics.
