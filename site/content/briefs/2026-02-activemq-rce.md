---
title: Active Exploitation of Apache ActiveMQ RCE Vulnerability (CVE-2023-46604)
slug: 2026-02-activemq-rce
description: CVE-2023-46604 is a remote code execution vulnerability affecting Apache ActiveMQ that is actively exploited in the wild by ransomware operators, allowing remote attackers to execute arbitrary shell commands.
date: "2026-02-25T09:22:01Z"
severities:
  - critical
actors:
  - LockBit
  - HelloKitty
tags:
  - activemq
  - rce
  - cve-2023-46604
  - ransomware
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://ccb.belgium.be/advisories/warning-new-rce-vulnerability-affecting-apache-activemq-cve-2023-46604-actively
  - https://nvd.nist.gov/vuln/detail/CVE-2023-46604
  - https://thedfirreport.com/2026/02/23/apache-activemq-exploit-leads-to-lockbit-ransomware/#case-summary
  - https://cybersecuritynews.com/hellokitty-ransomware-apache-activemq/
  - https://securityaffairs.com/153454/hacking/apache-activemq-cve-2023-46604-hellokitty-ransomare.html
  - https://en.wikipedia.org/wiki/Apache_ActiveMQ
rules:
  - title: Detect Suspicious ActiveMQ OpenWire Traffic
    description: Detects network connections to ActiveMQ brokers using the OpenWire protocol with unusual data patterns indicative of exploitation attempts of CVE-2023-46604.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - network_connection
      - zeek
  - title: Detect Suspicious Process Execution from ActiveMQ
    description: Detects processes spawned by the ActiveMQ service that are uncommon or known to be malicious, indicating potential RCE exploitation.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2023-46604 is a critical remote code execution (RCE) vulnerability affecting Apache ActiveMQ message brokers. This vulnerability allows a remote attacker with network access to the ActiveMQ broker to execute arbitrary shell commands by manipulating serialized class types within the OpenWire protocol. The vulnerability affects Apache ActiveMQ versions 5.16.0 before 5.16.7, 5.17.0 before 5.17.6, 5.18.0 before 5.18.3, and before 5.15.16, as well as corresponding versions of the Legacy OpenWire…
