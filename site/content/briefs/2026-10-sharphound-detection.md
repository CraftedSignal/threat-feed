---
title: Detection of SharpHound Active Directory Enumeration
slug: 2026-10-sharphound-detection
description: Attackers utilize the SharpHound tool for automated Active Directory enumeration to map network structures and identify targets for lateral movement and privilege escalation.
date: "2026-10-12T17:41:32Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - discovery
  - bloodhound
  - sharphound
  - ad-enumeration
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1069.001
    technique_name: 'Permission Groups Discovery: Local Groups'
    evidence: The following analytic detects the execution of SharpHound command-line arguments, specifically -collectionMethod and invoke-bloodhound.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1069.002
    technique_name: 'Permission Groups Discovery: Domain Groups'
    evidence: This activity is significant as SharpHound is commonly used for Active Directory enumeration.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087.001
    technique_name: 'Account Discovery: Local Account'
    evidence: This activity is significant as SharpHound is commonly used for Active Directory enumeration.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087.002
    technique_name: 'Account Discovery: Domain Account'
    evidence: This activity is significant as SharpHound is commonly used for Active Directory enumeration.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1482
    technique_name: Domain Trust Discovery
    evidence: This activity is significant as SharpHound is commonly used for Active Directory enumeration.
    confidence_band: high
rules:
  - title: Detect SharpHound Command-Line Arguments
    description: Detects the execution of SharpHound using known command-line arguments associated with AD enumeration, such as -collectionMethod and invoke-bloodhound.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1069.001
      - T1069.002
      - T1087.001
      - T1087.002
      - T1482
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to SIEM/EDR.
      owner: Detection Engineering
      due: 48h
      evidence: Analytic rule provided in the brief.
  hunt_leads:
    - lead: Search historical process logs for SharpHound command-line arguments.
      technique_id: T1069
      data_needed:
        - Process command line
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: SharpHound use is a strong indicator of reconnaissance.
---

SharpHound is a widely used collection utility for the BloodHound project, designed to perform comprehensive Active Directory (AD) enumeration. By querying AD objects, groups, and permissions, the tool assists attackers in identifying attack paths, discovering high-value accounts, and mapping domain trust relationships. This activity often serves as a reconnaissance phase preceding lateral movement, privilege escalation, or ransomware deployment, such as that observed in BlackSuit Ransomware campaigns. Detection is focused on identifying command-line arguments unique to the execution of the SharpHound binary or PowerShell script, specifically flagging indicators of the collection phase.

## Impact

Successful execution of SharpHound provides attackers with detailed visibility into domain infrastructure. This reconnaissance enables efficient targeting of domain controllers, administrative users, and sensitive file shares, significantly increasing the risk of data exfiltration and domain-wide compromise.

## Recommendation

Deploy the provided Sigma rule to monitor for suspicious process execution strings indicative of Active Directory enumeration. Ensure that Sysmon Event ID 1 or Windows Event ID 4688 is ingested with full command-line arguments to maintain visibility.
