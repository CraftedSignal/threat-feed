---
title: NCSC Warns of State-Sponsored Espionage via IP Cameras Targeting Critical Infrastructure
slug: 2026-07-ip-camera-espionage-warning
description: Russian state-sponsored actors, along with hacktivist groups and cybercriminals, are exploiting IP cameras to spy on critical infrastructure in NATO countries, including the Netherlands, prompting NCSC to advise organizations and home users to secure their devices through updates, network segmentation, and attack surface reduction.
date: "2026-07-11T10:14:10Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Russian state-sponsored actors
tags:
  - ip-camera
  - espionage
  - critical-infrastructure
  - state-sponsored
  - advisory
  - network-segmentation
  - security-best-practices
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
    evidence: Russian state-sponsored actors are hacking IP cameras to spy on (vital) infrastructure.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1074
    technique_name: Data Staged
    evidence: Russian state-sponsored actors are hacking IP cameras to spy on (vital) infrastructure.
    confidence_band: high
references:
  - https://www.ncsc.nl/alerts/beveilig-je-ip-cameras-om-spionage-van-statelijke-actoren-te-voorkomen
---

The Netherlands National Cyber Security Centre (NCSC) has issued a critical advisory warning that Russian state-sponsored actors are actively compromising IP cameras to conduct espionage against vital infrastructure within NATO countries, specifically including the Netherlands. While state-sponsored groups are a primary concern, the NCSC also observes hacktivist groups and cybercriminals exploiting these devices for their own objectives. This threat began to be observed prior to this advisory and remains ongoing. The widespread presence of IP cameras, both in organizational and residential settings, makes them an attractive and often vulnerable target. Attackers leverage these devices to gain visual surveillance capabilities or potentially as initial access points into broader networks. The NCSC emphasizes the urgency for organizations and private users to bolster the security of their IP camera systems to mitigate the risk of surveillance and unauthorized network access.

## Impact

The successful exploitation of IP cameras by state-sponsored actors, hacktivists, and cybercriminals poses a significant risk of espionage against critical infrastructure, leading to potential intelligence gathering on sensitive operations, physical layouts, and personnel movements. This could compromise national security interests within NATO countries, including the Netherlands. Beyond espionage, compromised cameras can serve as a beachhead for further network intrusions, allowing attackers to move laterally and access other systems, potentially leading to data exfiltration, service disruption, or further sabotage. The advisory highlights that these attacks are not confined to specific sectors but target a broad spectrum of infrastructure, raising concerns about the collective resilience of national assets against persistent threats.

## Recommendation

* Regularly update the firmware and software of all IP cameras to the latest versions to patch known vulnerabilities. Implement a robust vulnerability management program that includes all network-connected devices.
* Segment networks to isolate IP cameras from critical internal systems. Ensure that cameras are placed on a separate VLAN or network segment with restricted communication rules, allowing only necessary outbound connections. Monitor network connection logs for unauthorized traffic from camera segments.
* Reduce the attack surface by disabling unnecessary services and closing unused ports on IP cameras and associated network devices. Implement strong, unique passwords for all camera accounts, and consider using multi-factor authentication where available.
* Enable comprehensive logging on firewalls and network devices to monitor traffic to and from IP cameras for unusual patterns or connections to known malicious IP addresses or domains.
