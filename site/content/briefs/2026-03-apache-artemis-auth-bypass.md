---
title: Apache Artemis and ActiveMQ Artemis Authentication Bypass Vulnerability
slug: 2026-03-apache-artemis-auth-bypass
description: CVE-2026-27446 allows an unauthenticated remote attacker to inject malicious messages or exfiltrate data from Apache Artemis and ActiveMQ Artemis brokers due to a missing authentication check in the Core protocol.
date: "2026-03-05T09:31:38Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - apache-artemis
  - apache-activemq
  - authentication-bypass
  - message-injection
  - data-exfiltration
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1020
    technique_name: Automated Exfiltration
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1489
    technique_name: Service Stop
references:
  - https://lists.apache.org/thread/jwpsdc8tdxotm98od8n8n30fqlzoc8gg
  - https://thedfirreport.com/2026/02/23/apache-activemq-exploit-leads-to-lockbit-ransomware/
  - https://radar.offseq.com/threat/cve-2026-27446-cwe-306-missing-authentication-for--ed42be89
rules:
  - title: Detect Outbound Core Protocol Connection to Suspicious IP
    description: Detects outbound connections using the Core protocol to IP addresses not in the known good list.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
  - title: Detect Artemis Message Injection via Core Protocol
    description: Detects message injection attempts by monitoring for specific patterns or keywords within Core protocol messages.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

On March 5, 2026, the Centre for Cybersecurity Belgium (CCB) issued a warning regarding CVE-2026-27446, a critical authentication bypass vulnerability affecting Apache Artemis and Apache ActiveMQ Artemis. This vulnerability stems from a lack of proper authentication controls within the Core protocol used for communication between brokers. Successful exploitation allows unauthenticated remote attackers to force a target broker to establish an outbound Core federation connection to a rogue broker…
