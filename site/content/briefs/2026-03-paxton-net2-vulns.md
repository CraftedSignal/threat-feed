---
title: Vulnerabilities in Paxton Net2 Access Control Units
slug: 2026-03-paxton-net2-vulns
description: Vulnerabilities in Paxton Net2 Access Control Units (ACUs) could allow unauthorized remote access and control of secured doors, potentially affecting prisons and other high-security facilities.
date: "2026-03-19T22:15:35Z"
severities:
  - high
tags:
  - access-control
  - physical-security
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1018
    technique_name: Remote System Discovery
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://www.reddit.com/r/cybersecurity/comments/1rye92s/hacking_prison_doors_remotely_like_in_movies/
ioc_counts:
  url: 1
rules:
  - title: Detect Unusual User Agent to Net2 Devices
    description: Detects unusual user agents connecting to Net2 devices, which may indicate reconnaissance or exploit attempts.
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1595
    data_sources:
      - network_connection
      - windows
  - title: Detect Network Scan Activity Targeting Port 80
    description: Detects network scan activity targeting port 80, which is often used by web services.
    platform: sigma
    severity: low
    tactics:
      - reconnaissance
    techniques:
      - T1595
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

A Reddit post highlights potential vulnerabilities within Paxton Net2 Access Control Units (ACUs). While the specifics of the vulnerabilities are not detailed in the Reddit post itself, the linked article allegedly describes how these flaws can be exploited to remotely unlock doors controlled by the Net2 system, potentially impacting prisons or other facilities using this access control technology. The potential for remote exploitation raises significant concerns about physical security bypass…
