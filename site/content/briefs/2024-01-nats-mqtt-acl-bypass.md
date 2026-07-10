---
title: NATS.io MQTT ACL Bypass Vulnerability
slug: 2024-01-nats-mqtt-acl-bypass
description: A vulnerability in NATS.io versions before v2.12.6 or v2.11.15 allows MQTT clients to bypass ACL checks for MQTT subjects due to ACLs not being applied in the `$MQTT.>` namespace, potentially allowing unauthorized access and control of MQTT communications.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - nats.io
  - mqtt
  - acl-bypass
  - vulnerability
vendors:
  - NATS.io
products:
  - NATS server
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-jxxm-27vp-c3m5
rules:
  - title: Detect Suspicious MQTT Namespace Access
    description: Detects attempts to access the MQTT namespace $MQTT.> in NATS, potentially indicating an ACL bypass attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - network_connection
      - linux
  - title: Detect NATS Server Versions Vulnerable to MQTT ACL Bypass
    description: Detects NATS server versions that are vulnerable to the MQTT ACL bypass vulnerability (CVE-2026-33217) by analyzing server logs for version information.
    platform: sigma
    severity: medium
    tactics:
      - vulnerability
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

NATS.io is a high-performance open-source pub-sub distributed communication technology used in cloud, on-premise, IoT, and edge computing environments. A critical vulnerability exists in the NATS server that allows MQTT clients to bypass Access Control List (ACL) checks when using the MQTT client interface. Specifically, ACLs are not enforced in the `$MQTT.>` namespace, which handles MQTT subjects. This flaw affects NATS server versions prior to v2.12.6 and v2.11.15, potentially enabling malicious MQTT clients to publish or subscribe to topics they should not have access to, leading to information disclosure or unauthorized control of the NATS messaging system. The vulnerability is identified as CVE-2026-33217 and presents a significant security risk for organizations relying on NATS for secure communication.

## Attack Chain

1.  An attacker identifies a NATS server running a vulnerable version (prior to v2.12.6 or v2.11.15) with MQTT enabled.
2.  The attacker establishes an MQTT client connection to the NATS server.
3.  The attacker crafts MQTT PUBLISH or SUBSCRIBE messages targeting subjects within the `$MQTT.>` namespace.
4.  The NATS server, due to the vulnerability, fails to apply configured ACLs to the MQTT messages.
5.  The attacker successfully publishes or subscribes to MQTT topics without proper authorization.
6.  The attacker gains unauthorized access to MQTT data or control over MQTT devices connected to the NATS server.
7.  The attacker can then leverage the unauthorized access for malicious purposes such as data exfiltration or disruption of services.

## Impact

Successful exploitation of this vulnerability (CVE-2026-33217) can lead to unauthorized access to sensitive MQTT data within the NATS messaging system. This can affect any organization using NATS for MQTT communication, especially in IoT environments where MQTT is prevalent. The impact ranges from information disclosure to complete compromise of MQTT-controlled devices or services. The number of potential victims is dependent on the number of NATS deployments using MQTT functionality and running vulnerable versions, but given the widespread adoption of NATS, the potential impact is significant.

## Recommendation

*   Upgrade NATS server instances to version v2.12.6 or v2.11.15 or later to remediate CVE-2026-33217.
*   Deploy the provided Sigma rule `Detect Suspicious MQTT Namespace Access` to identify potential exploitation attempts targeting the `$MQTT.>` namespace.
*   Monitor NATS server logs for suspicious activity related to MQTT connections and subject access using the `$MQTT.>` namespace.
