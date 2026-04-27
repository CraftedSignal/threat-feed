---
title: Interlock Ransomware Campaign Targeting Enterprise Firewalls
slug: 2024-01-interlock-firewall-ransomware
description: The Interlock ransomware campaign is targeting enterprise firewalls to encrypt sensitive data and demand ransom payment.
date: "2026-03-19T05:33:30Z"
severities:
  - high
tags:
  - ransomware
  - firewall
  - network
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://www.reddit.com/r/blueteamsec/comments/1rxrzb9/interlock_ransomware_campaign_targeting/
  - https://aws.amazon.com/blogs/security/amazon-threat-intelligence-teams-identify-interlock-ransomware-campaign-targeting-enterprise-firewalls/
rules:
  - title: Detect Firewall Configuration Changes
    description: Detects unauthorized configuration changes on enterprise firewalls.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - firewall
      - vendor_firewall
  - title: Detect Failed Login Attempts to Firewall Management Interface
    description: Detects multiple failed login attempts to the firewall management interface, which could indicate a brute-force attack.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1110.001
    data_sources:
      - firewall
      - vendor_firewall
rules_count: 2
---

The Interlock ransomware campaign specifically targets enterprise firewalls. The campaign's objective is to encrypt sensitive data residing on or accessible through these firewalls, rendering systems inoperable and creating significant business disruption. While specific details about the initial discovery and scope of the campaign remain limited, its focus on firewalls suggests a targeted approach aimed at organizations heavily reliant on these devices for network security and perimeter…
