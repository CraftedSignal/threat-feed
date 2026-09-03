---
title: Detection of BloodHound and SharpHound Enumeration Tools
slug: 2026-09-bloodhound-sharphound
description: Adversaries utilize BloodHound and SharpHound to perform automated reconnaissance and enumeration of Active Directory environments, facilitating lateral movement and privilege escalation.
date: "2026-09-03T12:37:50Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - reconnaissance
  - active-directory
  - windows
  - hacktool
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
    evidence: Detects command line parameters used by Bloodhound and Sharphound hack tools
    confidence_band: high
rules:
  - title: Detect BloodHound and SharpHound Execution
    description: Detects command line parameters and file metadata associated with BloodHound and SharpHound hack tools.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - execution
    techniques:
      - T1059.001
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
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to SIEM
      owner: Detection Engineering
      due: 24h
      evidence: Rule provided by sigma-hq
  hunt_leads:
    - lead: Search for rare process execution of SharpHound.exe
      technique_id: T1087
      data_needed:
        - Process creation events
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Source documentation of tool usage
---

BloodHound and its data ingestor, SharpHound, are widely utilized by threat actors to map and analyze Active Directory attack paths. By enumerating domain objects, sessions, and group memberships, these tools enable attackers to identify misconfigurations that lead to privilege escalation or lateral movement. SharpHound typically executes as a standalone binary or via PowerShell, generating JSON output that is then imported into the BloodHound graph database for visual analysis. Given the tool's effectiveness in identifying complex trust relationships and high-value targets within a domain, its usage is a strong indicator of an active discovery phase by a motivated adversary. Monitoring for specific command-line arguments and file metadata associated with SharpHound is critical for early detection of reconnaissance efforts within Windows environments.

## Attack Chain

1. Attacker gains initial foothold or executes code within the domain environment.
2. Attacker drops SharpHound.exe or invokes the SharpHound PowerShell module onto the host.
3. SharpHound initiates enumeration of Active Directory using specialized collection methods such as -CollectionMethod All.
4. SharpHound executes port scans or session enumeration to map network connectivity and user sessions.
5. The tool performs path discovery, identifying domain controllers and group memberships.
6. Data is collected into JSON files on the local disk via the -JsonFolder and -ZipFileName parameters.
7. The compressed collection files are exfiltrated from the environment for offline analysis.
8. Attacker uses the graph analysis to identify paths for privilege escalation or lateral movement.

## Impact

Successful execution of BloodHound provides an adversary with a comprehensive roadmap of an organization's Active Directory security posture. This significantly increases the risk of successful account takeover, domain dominance, and data exfiltration, as attackers can identify and exploit non-obvious attack paths that standard security controls may overlook.

## Recommendation

* Deploy the provided Sigma rule to detect known SharpHound command-line patterns and binary metadata.
* Enable Sysmon process-creation logging to capture CommandLine, Product, and Company fields.
* Investigate occurrences of SharpHound execution to determine if unauthorized domain enumeration is taking place.
* Restrict the ability of non-administrative users to execute tools that perform automated LDAP queries against domain controllers.
