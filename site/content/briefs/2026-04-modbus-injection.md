---
title: 'CVE-2026-4436: Modbus Odorant Injection Manipulation'
slug: 2026-04-modbus-injection
description: A low-privileged remote attacker can exploit CVE-2026-4436 by sending Modbus packets to manipulate register values controlling odorant injection in gas lines, potentially leading to hazardous conditions.
date: "2026-04-09T20:16:27Z"
severities:
  - high
type: advisory
types:
  - advisory
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

CVE-2026-4436 is a vulnerability affecting systems that use Modbus for controlling odorant injection in gas lines. A low-privileged remote attacker can exploit this vulnerability by sending crafted Modbus packets to manipulate register values that serve as inputs to the odorant injection logic. This can result in either too much or too little odorant being injected into the gas line, which can have severe safety and operational consequences. The vulnerability was reported by ICS-CERT and affects systems utilizing Modbus protocol for industrial control. Successful exploitation requires network access to the Modbus interface but does not require authentication due to missing authentication controls (CWE-306).

## Attack Chain

1.  Attacker gains network access to the Modbus interface of the odorant injection system.
2.  Attacker identifies the Modbus registers responsible for controlling odorant injection parameters.
3.  Attacker crafts Modbus packets designed to modify the identified registers.
4.  Attacker sends the malicious Modbus packets to the target system.
5.  The system processes the packets and modifies the register values.
6.  Odorant injection logic uses the manipulated register values.
7.  The system injects either too much or too little odorant into the gas line.
8.  The altered odorant level creates potentially hazardous conditions or operational disruptions.

## Impact

Successful exploitation of CVE-2026-4436 can lead to dangerous situations due to incorrect odorant levels in gas lines. Too little odorant can make gas leaks undetectable, increasing the risk of explosions. Conversely, too much odorant can cause health concerns and damage equipment. The potential impact ranges from localized safety incidents to widespread disruptions in gas distribution, affecting residential, commercial, and industrial sectors.

## Recommendation

*   Implement proper authentication and authorization mechanisms for Modbus communications to mitigate CWE-306 (Missing Authentication for Critical Function), as highlighted in the CVE description.
*   Monitor Modbus traffic for suspicious activity, such as unexpected register writes, using the provided Sigma rule targeting Modbus write operations.
*   Segment the network to isolate the Modbus devices from untrusted networks to limit the attack surface, as the vulnerability can be exploited remotely.
*   Deploy the Sigma rule to detect Modbus write operations and tune for your environment to filter out benign Modbus traffic.
*   Reference ICS-CERT advisory ICSA-26-099-02 for vendor-specific patches and mitigation strategies.
