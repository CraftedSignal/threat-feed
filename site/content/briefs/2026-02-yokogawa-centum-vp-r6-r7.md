---
title: Yokogawa CENTUM VP R6 and R7 Vulnerabilities Lead to Potential Denial of Service and Arbitrary Code Execution
slug: 2026-02-yokogawa-centum-vp-r6-r7
description: Multiple vulnerabilities in Yokogawa CENTUM VP R6 and R7 Vnet/IP Interface Package can be exploited by sending maliciously crafted packets, leading to denial-of-service or arbitrary code execution.
date: "2026-02-27T12:00:00Z"
severities:
  - high
tags:
  - ics
  - denial-of-service
  - out-of-bounds write
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1040
    technique_name: Network Sniffing
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-057-09
  - https://nvd.nist.gov/vuln/detail/CVE-2025-1924
  - https://nvd.nist.gov/vuln/detail/CVE-2025-48019
  - https://nvd.nist.gov/vuln/detail/CVE-2025-48020
  - https://nvd.nist.gov/vuln/detail/CVE-2025-48021
  - https://nvd.nist.gov/vuln/detail/CVE-2025-48022
  - https://nvd.nist.gov/vuln/detail/CVE-2025-48023
  - https://web-material3.yokogawa.com/1/39281/files/YSAR-26-0002-E.pdf
rules:
  - title: Detect Possible Yokogawa CENTUM VP DoS Attempt via Malformed Packets
    description: Detects network connections with unusual characteristics that may indicate an attempt to exploit vulnerabilities in Yokogawa CENTUM VP systems, leading to a denial-of-service.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Vnet/IP Process Termination (Simulated)
    description: This rule simulates detection of a process termination, which is the result of some of the vulnerabilities. Adjust the Image to the actual Vnet/IP process name if known.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Yokogawa CENTUM VP is a distributed control system (DCS) used in critical infrastructure sectors such as critical manufacturing, energy, and food and agriculture worldwide. CISA has released an advisory detailing multiple vulnerabilities (CVE-2025-1924, CVE-2025-48019, CVE-2025-48020, CVE-2025-48021, CVE-2025-48022, CVE-2025-48023) affecting the Vnet/IP Interface Package for CENTUM VP R6 (VP6C3300) and R7 (VP7C3300) versions <= R1.07.00. Successful exploitation of these vulnerabilities could…
