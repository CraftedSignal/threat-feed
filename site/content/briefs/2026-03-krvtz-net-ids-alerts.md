---
title: 'KRVTZ-NET IDS Alerts Analysis: Network Scanning and Exploitation Attempts'
slug: 2026-03-krvtz-net-ids-alerts
description: Multiple IDS alerts indicate potential network reconnaissance, vulnerability exploitation attempts targeting Fortigate VPN (CVE-2023-27997), and ColdFusion servers originating from various IP addresses on March 13, 2026.
date: "2026-03-13T20:52:20Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - network-scanning
  - vulnerability-exploitation
  - fortigate
  - coldfusion
  - cve-2023-27997
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1040
    technique_name: Network Sniffing
references:
  - https://www.circl.lu/doc/misp/feed-osint/d6292c9e-e1c1-4697-8a72-3d50562a29bb.json
rules:
  - title: Detect Suspicious User Agent Strings
    description: Detects requests with suspicious user agent strings such as '_TEST_' and 'InfoBot'.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1595.001
    data_sources:
      - web
      - apache|nginx|iis
  - title: Detect ColdFusion Componentutils Access
    description: Detects access to the ColdFusion componentutils endpoint, potentially indicating vulnerability exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - web
      - apache|nginx|iis
  - title: Detect Request to Hidden Environment File
    description: Detects requests to hidden environment files (.env) indicating potential information leakage attempt.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1592
    data_sources:
      - web
      - apache|nginx|iis
rules_count: 3
---

On March 13, 2026, KRVTZ-NET IDS systems generated a series of alerts indicative of network scanning and attempted exploitation. The alerts highlight suspicious activity originating from a range of IP addresses, suggesting a widespread campaign rather than a targeted attack from a single actor. Specific alerts include repeated GET requests to `/remote/logincheck`, potentially targeting the Fortigate VPN vulnerability CVE-2023-27997, as well as requests for hidden environment files and attempts…
