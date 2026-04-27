---
title: 'CVE-2026-4436: Modbus Odorant Injection Manipulation'
slug: 2026-04-modbus-injection
description: A low-privileged remote attacker can exploit CVE-2026-4436 by sending Modbus packets to manipulate register values controlling odorant injection in gas lines, potentially leading to hazardous conditions.
date: "2026-04-09T20:16:27Z"
severities:
  - high
tags:
  - cve
  - modbus
  - industrial-control-system
  - odorant-injection
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-4436
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4436
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-099-02
rules:
  - title: Detect Modbus Write Single Register
    description: Detects Modbus write single register operations which could indicate malicious manipulation of control parameters.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1491.001
    data_sources:
      - network_connection
      - zeek
  - title: Detect Modbus Write Multiple Registers
    description: Detects Modbus write multiple registers operations which could indicate widespread manipulation of control parameters.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1491.001
    data_sources:
      - network_connection
      - zeek
rules_count: 2
---

CVE-2026-4436 is a vulnerability affecting systems that use Modbus for controlling odorant injection in gas lines. A low-privileged remote attacker can exploit this vulnerability by sending crafted Modbus packets to manipulate register values that serve as inputs to the odorant injection logic. This can result in either too much or too little odorant being injected into the gas line, which can have severe safety and operational consequences. The vulnerability was reported by ICS-CERT and…
