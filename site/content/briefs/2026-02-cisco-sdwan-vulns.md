---
title: Ongoing Exploitation of Cisco SD-WAN Systems
slug: 2026-02-cisco-sdwan-vulns
description: Malicious actors are actively exploiting CVE-2026-20127 for initial access and CVE-2022-20775 for privilege escalation and persistence on Cisco SD-WAN systems globally.
date: "2026-02-25T12:00:00Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cisco-sdwan
  - vulnerability
  - exploitation
  - network
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://www.cisa.gov/news-events/alerts/2026/02/25/cisa-and-partners-release-guidance-ongoing-global-exploitation-cisco-sd-wan-systems
  - https://www.cve.org/CVERecord?id=CVE-2026-20127
  - https://www.cve.org/CVERecord?id=CVE-2022-20775
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-rpa-EHchtZk
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v
  - https://sec.cloudapps.cisco.com/security/center/resources/Cisco-Catalyst-SD-WAN-HardeningGuide
rules:
  - title: Detect SD-WAN Authentication Bypass Attempt
    description: Detects attempts to exploit CVE-2026-20127, an authentication bypass vulnerability in Cisco SD-WAN systems, by monitoring for abnormal authentication patterns.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1588.004
    data_sources:
      - network_connection
      - cisco
  - title: SD-WAN Configuration Change Detection
    description: Detects suspicious configuration changes within Cisco SD-WAN systems which might indicate malicious activity after exploiting CVE-2022-20775.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1078
    data_sources:
      - file_event
      - linux
  - title: Detect SD-WAN Remote Syslog Configuration Modification
    description: Detects modifications to syslog settings, potentially indicating an attacker trying to disable or redirect logging after compromising the system via CVE-2022-20775
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - file_event
      - linux
rules_count: 3
---

CISA and its partners have observed malicious cyber actors targeting and compromising Cisco SD-WAN systems across various organizations globally. The attackers are leveraging CVE-2026-20127, an authentication bypass vulnerability, for initial access. Following successful exploitation of CVE-2026-20127, the attackers escalate privileges and establish long-term persistence within the compromised SD-WAN systems using CVE-2022-20775. In response to this active exploitation, CISA issued Emergency…
