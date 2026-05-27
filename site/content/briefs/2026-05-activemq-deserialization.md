---
title: Critical Deserialization Vulnerability in Apache ActiveMQ NMS AMQP Client (CVE-2025-54539)
slug: 2026-05-activemq-deserialization
description: A critical deserialization of untrusted data vulnerability (CVE-2025-54539) exists in Apache ActiveMQ NMS AMQP Client <= v2.3.0, where an attacker controlling or impersonating an AMQP broker can send malicious serialized data that the client deserializes unsafely, allowing arbitrary code execution on the client system.
date: "2026-05-27T19:03:21Z"
type: threat
types:
  - threat
severities:
  - critical
cpes:
  - cpe:2.3:a:apache:activemq_nms_amqp:*:*:*:*:*:*:*:*
tags:
  - deserialization
  - rce
  - activemq
  - cve-2025-54539
  - windows
vendors:
  - Apache
products:
  - ActiveMQ NMS AMQP Client <= v2.3.0
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1566
    technique_name: Phishing
cves:
  - id: CVE-2025-54539
    cvss: 9.8
    epss: 0.01309
references:
  - https://ccb.belgium.be/advisories/warning-critical-deserialization-untrusted-data-vulnerability-apache-activemq-nms-amqp
  - https://lists.apache.org/thread/9k684j07ljrshy3hxwhj5m0xjmkz1g2n
  - https://nvd.nist.gov/vuln/detail/CVE-2025-54539
  - https://www.tenable.com/cve/CVE-2025-54539
rules:
  - title: Detect Suspicious ActiveMQ NMS AMQP Client Deserialization
    description: Detects CVE-2025-54539 exploitation — monitors for processes that are likely spawned from deserialization within the ActiveMQ NMS AMQP Client.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1555
      - T1566.001
    data_sources:
      - process_creation
      - windows
  - title: Detect ActiveMQ NMS AMQP Client Connecting to Uncommon Ports
    description: Detects ActiveMQ NMS AMQP Client connecting to ports that are not the default AMQP ports.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Apache ActiveMQ NMS AMQP Client, a .NET messaging library, is vulnerable to a critical deserialization of untrusted data vulnerability (CVE-2025-54539). An attacker controlling or impersonating an AMQP broker can send maliciously crafted serialized data to the client. The Apache ActiveMQ NMS AMQP Client deserializes this data unsafely, leading to arbitrary code execution on the client system. This vulnerability affects all NMS AMQP releases up to and including version 2.3.0. A proof-of-concept exploit is publicly available, increasing the risk of exploitation. Successful exploitation can lead to full compromise of confidentiality, integrity, and availability of the client system. It is fixed in version 2.4.0.

## Attack Chain

1. The attacker gains control of, or impersonates, an AMQP broker.
2. The .NET application using the vulnerable Apache ActiveMQ NMS AMQP Client initiates a connection to the malicious or compromised AMQP broker.
3. The attacker sends a malicious AMQP message containing a crafted serialized object to the client.
4. The client receives the malicious AMQP message from the broker.
5. The Apache ActiveMQ NMS AMQP Client attempts to deserialize the received data using .NET binary deserialization.
6. Due to insufficient validation, the malicious serialized object triggers the instantiation of arbitrary classes and execution of associated code paths during deserialization.
7. The attacker achieves remote code execution (RCE) in the context of the client process.
8. The attacker gains full control over the compromised system, enabling activities such as data exfiltration, malware installation, or further lateral movement.

## Impact

Successful exploitation of CVE-2025-54539 allows a remote attacker to execute arbitrary code on a vulnerable system running the Apache ActiveMQ NMS AMQP Client. This can lead to a complete compromise of the affected system, including loss of confidentiality, integrity, and availability. Given the messaging library's role, a successful attack could disrupt critical business processes relying on AMQP communication. Due to the availability of a public PoC, the risk of exploitation is elevated.

## Recommendation

*   Upgrade to Apache ActiveMQ NMS AMQP Client version 2.4.0 or later to patch CVE-2025-54539.
*   Monitor network traffic for connections to unusual or suspicious AMQP brokers, and implement network segmentation to restrict connections to trusted brokers only.
*   Implement application whitelisting to prevent execution of unauthorized binaries, limiting the impact of potential RCE.
*   Enable process monitoring and logging to detect suspicious process creation events that may indicate successful exploitation of CVE-2025-54539.
*   As a long-term hardening strategy, migrate away from .NET binary serialization, as recommended by Apache.
*   Deploy the Sigma rule "Detect Suspicious ActiveMQ NMS AMQP Client Deserialization" to your SIEM and tune for your environment.
