---
title: Multiple Network Intrusion Attempts Detected
slug: 2026-03-network-intrusion-attempts
description: Multiple network-based intrusion attempts were detected on 2026-03-14, targeting PHP information exposure, Fortigate VPN exploitation, sensitive file access, and credential exposure.
date: "2026-03-14T23:06:48Z"
severities:
  - high
tags:
  - network-intrusion
  - vulnerability-exploitation
  - information-disclosure
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
references:
  - https://www.circl.lu/doc/misp/feed-osint/14501f7e-9084-4cba-8229-66baead78066.json
ioc_counts:
  ip: 8
rules:
  - title: Detect Fortigate CVE-2023-27997 Exploitation Attempts
    description: Detects repeated GET requests to /remote/logincheck, indicative of CVE-2023-27997 exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - zeek
  - title: Detect Requests to Hidden Environment Files
    description: Detects HTTP requests to common hidden environment file locations.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1595.001
    data_sources:
      - network_connection
      - zeek
  - title: Detect Suspicious User Agent _TEST_
    description: Detects HTTP requests with the User-Agent string '_TEST_'.
    platform: sigma
    severity: low
    tactics:
      - discovery
    data_sources:
      - network_connection
      - zeek
rules_count: 3
---

On 2026-03-14, network intrusion detection systems (IDS) identified multiple suspicious activities originating from various IP addresses. These activities included attempts to access PHP information pages, exploit the Fortigate VPN vulnerability CVE-2023-27997, request hidden environment files, probe for SFTP/FTP password exposure, request Visual Studio Code sftp configuration files, and use a suspicious user agent string. While the specific actor remains unknown, the breadth of probes suggests…
