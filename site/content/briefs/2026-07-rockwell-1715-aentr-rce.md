---
title: Critical Unauthenticated Remote Access Vulnerability in Rockwell Automation 1715-AENTR EtherNet/IP Adapter (CVE-2026-10577)
slug: 2026-07-rockwell-1715-aentr-rce
description: A critical unauthenticated remote access vulnerability, CVE-2026-10577, in Rockwell Automation 1715-AENTR EtherNet/IP Adapter versions <=3.003 allows an attacker to exploit a network-accessible debug port with missing privilege controls, enabling remote command-line interface access to read/delete files, modify memory, and change I/O states, impacting the confidentiality, integrity, and availability of industrial control systems.
date: "2026-07-14T15:48:34Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - ics
  - ot
  - vulnerability
  - critical-infrastructure
  - remote-code-execution
vendors:
  - Rockwell Automation
products:
  - 1715-AENTR EtherNet/IP Adapter <=3.003
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The affected product exposes a network-accessible debug port that does not enforce proper privilege controls, allowing unauthenticated remote access to intrusive command-line interface (CLI) commands.
    confidence_band: high
cves:
  - id: CVE-2026-10577
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-195-04
  - https://www.cve.org/CVERecord?id=CVE-2026-10577
---

CISA has released an advisory regarding a critical security vulnerability, CVE-2026-10577, affecting Rockwell Automation 1715-AENTR EtherNet/IP Adapter devices, specifically versions 3.003 and earlier. This flaw stems from a network-accessible debug port that lacks proper authentication and privilege enforcement, granting unauthenticated remote attackers direct access to intrusive command-line interface (CLI) commands. This exposure poses a significant risk to critical infrastructure sectors, including Energy, Water and Wastewater, and Critical Manufacturing, globally. Successful exploitation could lead to severe impacts on the operational technology environment, allowing threat actors to manipulate files, halt critical tasks, alter memory contents, and change I/O states, thereby compromising the affected device's confidentiality, integrity, and availability. While CISA reports no known public exploitation at this time, the high severity (CVSS v3.1 10.0) underscores the urgency for immediate remediation.

## Attack Chain

1. An unauthenticated attacker identifies a Rockwell Automation 1715-AENTR EtherNet/IP Adapter device running an affected firmware version (<=3.003) via network scanning.
2. The attacker establishes a network connection to the device's exposed debug port, which lacks proper authentication mechanisms.
3. Leveraging the missing authentication, the attacker gains unauthenticated remote access to the device's intrusive command-line interface (CLI).
4. The attacker executes CLI commands to read or delete files on the device's file system.
5. The attacker issues commands to stop tasks, potentially disrupting critical industrial processes.
6. The attacker exploits the CLI access to modify the device's memory, potentially altering operational parameters or firmware.
7. The attacker manipulates I/O states, gaining control over physical processes connected to the adapter.
8. The final objective is complete compromise of the device, leading to impacts on confidentiality, integrity, and availability of the connected industrial control system.

## Impact

Successful exploitation of CVE-2026-10577 allows an unauthenticated attacker to gain full control over the Rockwell Automation 1715-AENTR EtherNet/IP Adapter, leading to severe operational disruptions. Attackers can read or delete device files, stop critical tasks, modify memory, and alter I/O states, directly affecting the operational integrity and safety of industrial processes. This vulnerability places critical infrastructure sectors, including Energy, Water and Wastewater, and Critical Manufacturing, at high risk. Compromise of these devices could result in unauthorized process changes, data corruption, denial of service, or even physical damage to machinery and infrastructure, with potential for widespread outages and safety hazards. Given the global deployment of these devices, the potential for broad impact across multiple regions is significant.

## Recommendation

* Update Rockwell Automation 1715-AENTR EtherNet/IP Adapter devices to version 3.011 or later to remediate CVE-2026-10577.
* Minimize network exposure for all control system devices and systems, ensuring the Rockwell Automation 1715-AENTR EtherNet/IP Adapter is not accessible from the internet.
* Implement network segmentation by locating control system networks and remote devices behind firewalls and isolating them from business networks.
* When remote access to the Rockwell Automation 1715-AENTR EtherNet/IP Adapter is necessary, utilize secure methods such as Virtual Private Networks (VPNs) and ensure VPNs are updated to the most current version.
