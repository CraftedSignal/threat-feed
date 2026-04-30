---
title: Vulnerabilities in Paxton Net2 Access Control Units
slug: 2026-03-paxton-net2-vulns
description: Vulnerabilities in Paxton Net2 Access Control Units (ACUs) could allow unauthorized remote access and control of secured doors, potentially affecting prisons and other high-security facilities.
date: "2026-03-19T22:15:35Z"
type: advisory
types:
  - advisory
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
iocs:
  - type: url
    value: https://it4sec.substack.com/p/hacking-prison-doors-remotely-like
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

A Reddit post highlights potential vulnerabilities within Paxton Net2 Access Control Units (ACUs). While the specifics of the vulnerabilities are not detailed in the Reddit post itself, the linked article allegedly describes how these flaws can be exploited to remotely unlock doors controlled by the Net2 system, potentially impacting prisons or other facilities using this access control technology. The potential for remote exploitation raises significant concerns about physical security bypass. Defenders should investigate their exposure to this product and monitor for anomalous network activity to or from these devices.

## Attack Chain

1.  Attacker identifies a vulnerable Paxton Net2 ACU connected to the network.
2.  Attacker leverages an unspecified vulnerability to gain unauthorized access to the ACU.
3.  Attacker authenticates or bypasses authentication on the ACU to gain control.
4.  Attacker sends a command to the ACU to unlock a specific door.
5.  The ACU executes the command, releasing the electronic lock on the door.
6.  Attacker gains physical access through the unlocked door.

## Impact

Successful exploitation of these vulnerabilities could lead to unauthorized physical access to secured areas. In a prison setting, this could enable escapes and security breaches. Other facilities, such as data centers or government buildings, could also be at risk. The number of affected facilities is unknown.

## Recommendation

*   Investigate internal usage of Paxton Net2 ACUs and determine firmware versions.
*   Monitor network traffic to and from Net2 ACUs for unexpected communications, as highlighted in the overview.
*   Review logs from Net2 ACUs for suspicious activity, if available, focusing on unusual unlock events.
*   Deploy the Sigma rule for unexpected user agents to detect reconnaissance activity targeting these devices.
*   Block access to `https://it4sec.substack.com/p/hacking-prison-doors-remotely-like` at the web proxy, as this site may contain exploit information.
