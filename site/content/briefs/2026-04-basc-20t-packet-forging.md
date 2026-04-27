---
title: Contemporary Controls BASC 20T Packet Forging Vulnerability
slug: 2026-04-basc-20t-packet-forging
description: CVE-2025-13926 describes a vulnerability in Contemporary Controls BASC 20T that allows an attacker to sniff network traffic and forge packets to make arbitrary requests, potentially leading to unauthorized actions.
date: "2026-04-09T20:16:23Z"
severities:
  - critical
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

CVE-2025-13926 is a critical vulnerability affecting Contemporary Controls BASC 20T. An attacker can exploit this vulnerability by capturing network traffic and forging packets, enabling them to send arbitrary requests to the device. This is achieved by sniffing network traffic, extracting necessary data for packet construction, and then crafting malicious packets to interact with the BASC 20T. The vulnerability has a CVSS v3.1 score of 9.8 and a CVSS v4.0 score of 9.3, highlighting the…
