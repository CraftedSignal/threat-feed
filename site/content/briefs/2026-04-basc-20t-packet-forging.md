---
title: Contemporary Controls BASC 20T Packet Forging Vulnerability
slug: 2026-04-basc-20t-packet-forging
description: CVE-2025-13926 describes a vulnerability in Contemporary Controls BASC 20T that allows an attacker to sniff network traffic and forge packets to make arbitrary requests, potentially leading to unauthorized actions.
date: "2026-04-09T20:16:23Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve-2025-13926
  - basc-20t
  - packet-forging
  - industrial-control-system
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1595
    technique_name: Active Scanning
cves:
  - id: CVE-2025-13926
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-13926
  - https://github.com/cisagov/CSAF/blob/develop/csaf_files/OT/white/2026/icsa-26-099-01.json
  - https://www.ccontrols.com/support/contacttech.htm
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-099-01
rules:
  - title: Detect Suspicious BASC 20T Network Traffic
    description: Detects potentially malicious network traffic to Contemporary Controls BASC 20T devices by monitoring for unusual packet sizes or patterns.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1595.002
    data_sources:
      - network_connection
      - zeek
  - title: Detect Crafted Packet Size Anomaly
    description: Detects unusual packet sizes to destination port likely used by BASC 20T
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1595.002
    data_sources:
      - network_connection
      - zeek
rules_count: 2
---

CVE-2025-13926 is a critical vulnerability affecting Contemporary Controls BASC 20T. An attacker can exploit this vulnerability by capturing network traffic and forging packets, enabling them to send arbitrary requests to the device. This is achieved by sniffing network traffic, extracting necessary data for packet construction, and then crafting malicious packets to interact with the BASC 20T. The vulnerability has a CVSS v3.1 score of 9.8 and a CVSS v4.0 score of 9.3, highlighting the severity and potential impact. Successful exploitation could lead to unauthorized access, modification of settings, or disruption of operations managed by the BASC 20T. This vulnerability was reported by ICS-CERT and assigned CWE-807, which describes reliance on untrusted inputs in a security decision.

## Attack Chain

1.  Attacker performs network reconnaissance to identify a vulnerable Contemporary Controls BASC 20T device.
2.  Attacker passively sniffs network traffic to and from the BASC 20T device.
3.  The attacker analyzes captured network packets to understand the communication protocol and packet structure used by the BASC 20T.
4.  Attacker identifies fields within the packets that can be manipulated to achieve the desired malicious actions.
5.  The attacker crafts a forged packet with modified fields to perform an arbitrary request (e.g., changing settings, issuing commands).
6.  The attacker injects the forged packet into the network, targeting the BASC 20T device.
7.  The BASC 20T processes the forged packet without proper validation, executing the attacker's arbitrary request.
8.  The attacker gains unauthorized control or access to the BASC 20T, potentially disrupting operations.

## Impact

Successful exploitation of CVE-2025-13926 allows an attacker to make arbitrary requests to the Contemporary Controls BASC 20T. This could lead to unauthorized modification of device settings, disruption of critical control processes, or potentially complete device compromise. The affected BASC 20T devices are often used in industrial control systems (ICS), so a successful attack could have significant consequences for the targeted organization, including operational downtime, equipment damage, or safety hazards.

## Recommendation

*   Monitor network traffic for unusual patterns or malformed packets originating from or directed to Contemporary Controls BASC 20T devices (network_connection category).
*   Implement network segmentation to limit the blast radius of a potential compromise.
*   Deploy the Sigma rules provided to detect suspicious network activity related to forged packets targeting BASC 20T devices.
*   Contact Contemporary Controls for available patches or mitigations for CVE-2025-13926 (references section).
