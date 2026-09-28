---
title: Unsafe Reflection Vulnerability in Apache ActiveMQ Artemis
slug: 2026-09-activemq-artemis-reflection
description: Apache ActiveMQ Artemis versions prior to 2.34.0 are vulnerable to remote code execution or state manipulation via insecure reflection in the FederationStreamConnectMessage.getFederationPolicy() method.
date: "2026-09-28T14:15:05Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:apache:activemq_artemis:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - deserialization
  - message-broker
vendors:
  - Apache
products:
  - ActiveMQ Artemis (< 2.34.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: An authenticated federation peer can send a FEDERATION_DOWNSTREAM_CONNECT packet with a crafted class name, causing the broker to load and instantiate arbitrary classes.
    confidence_band: high
cves:
  - id: CVE-2026-101292
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-101292
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  mitigation_plan:
    - priority: immediate
      action: Upgrade Apache ActiveMQ Artemis to 2.34.0 or later
      owner: IT Operations
      addresses: CVE-2026-101292
      evidence: Apache ActiveMQ Artemis before 2.34.0 contains an unsafe reflection vulnerability
---

Apache ActiveMQ Artemis versions prior to 2.34.0 are susceptible to an unsafe reflection vulnerability residing within the FederationStreamConnectMessage.getFederationPolicy() method. The vulnerability arises because the class name (clazz) is read directly from the CORE protocol wire buffer without undergoing sufficient type validation before being passed to Class.forName(clazz).getConstructor().newInstance(). 

An authenticated attacker acting as a federation peer can transmit a specifically crafted FEDERATION_DOWNSTREAM_CONNECT packet to the broker. This packet forces the broker to instantiate arbitrary classes accessible within the Artemis module classloader. As a side effect of this instantiation, static initializers and no-argument constructors are executed. This behavior allows for malicious outcomes, including denial of service, memory exhaustion through excessive classloading, or unauthorized modification of the broker's internal state. This vulnerability poses a significant risk to the integrity and availability of message brokers configured for federation in enterprise environments.

## Impact

Successful exploitation allows an authenticated peer to trigger arbitrary class instantiation within the broker's process. This can lead to system-wide denial of service, resource exhaustion, and potential compromise of the broker state. Given the role of ActiveMQ in enterprise messaging, this could disrupt critical business processes and data flow across internal and hybrid infrastructure.

## Recommendation

1. Upgrade Apache ActiveMQ Artemis to version 2.34.0 or later immediately to resolve the reflection flaw.
2. Restrict federation configuration to trusted peers only and implement strict network access controls to limit access to the CORE protocol ports.
3. Conduct an audit of existing federation setups to identify and remove unauthorized or unknown federation peers.
4. Enable protocol-level logging to capture traffic patterns associated with FEDERATION_DOWNSTREAM_CONNECT packets for forensic analysis.
