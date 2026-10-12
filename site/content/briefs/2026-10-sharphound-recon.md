---
title: Detection of SharpHound Active Directory Enumeration Tool
slug: 2026-10-sharphound-recon
description: SharpHound is a widely used tool for Active Directory enumeration, enabling attackers to perform reconnaissance, map network relationships, and identify paths for lateral movement and privilege escalation.
date: "2026-10-12T17:41:50Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - reconnaissance
  - discovery
  - active-directory
  - windows
  - tool-usage
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1069
    technique_name: Permission Groups Discovery
    evidence: SharpHound is a tool used for Active Directory enumeration, often by attackers during the reconnaissance phase.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
    evidence: SharpHound is a tool used for Active Directory enumeration, often by attackers during the reconnaissance phase.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1482
    technique_name: Domain Trust Discovery
    evidence: SharpHound is a tool used for Active Directory enumeration, often by attackers during the reconnaissance phase.
    confidence_band: high
references:
  - https://attack.mitre.org/software/S0521/
  - https://github.com/BloodHoundAD/SharpHound3
  - https://thedfirreport.com/?s=bloodhound
rules:
  - title: Detect SharpHound Binary Execution
    description: Detects the execution of SharpHound.exe by identifying its process name or original file name attribute.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1069.001
      - T1087.001
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
    - action: Deploy the Sigma rule to monitor for SharpHound binary execution
      owner: Detection Engineering
      due: 24h
      evidence: Source provides specific file and process metadata for detection
  hunt_leads:
    - lead: Search for processes with the original file name 'SharpHound.exe' in historical EDR logs
      technique_id: T1069
      data_needed:
        - EDR process creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: SharpHound is a tool used for Active Directory enumeration
  mitigation_plan:
    - priority: short_term
      action: Enable PowerShell Constrained Language Mode to restrict unauthorized tool execution
      owner: IT Operations
      addresses: Adversary TTPs
      evidence: SharpHound is used to facilitate lateral movement
---

SharpHound is the data collector binary for the BloodHound project, frequently utilized by attackers during the post-exploitation reconnaissance phase to map complex Active Directory relationships. By querying domain controllers and other systems, SharpHound extracts information regarding group memberships, user permissions, and object dependencies. This data is then imported into BloodHound to visualize attack paths, such as shortest paths to Domain Admin. The binary is often executed on compromised endpoints to gather intelligence that informs subsequent lateral movement, privilege escalation, and domain dominance strategies. Detecting the presence of this specific binary via EDR process metadata provides high-fidelity signals for identifying active reconnaissance within a Windows environment.

## Attack Chain

1. Attacker gains initial access to a workstation or server within the domain.
2. Attacker drops the `SharpHound.exe` binary onto the local disk.
3. Attacker executes `SharpHound.exe` with specific flags (e.g., --CollectionMethod All) to initiate domain discovery.
4. SharpHound performs LDAP queries against Domain Controllers to enumerate users, groups, and computers.
5. Tool performs recursive queries to map object ownership and access control lists (ACLs).
6. Captured data is exported to a JSON or CSV file by the binary.
7. Attacker exfiltrates the output file to their command-and-control infrastructure for analysis.
8. Attacker uses the analyzed data to compromise high-value targets or escalate privileges within the Active Directory environment.

## Impact

Successful reconnaissance with SharpHound allows attackers to map internal network architecture and identify hidden privilege escalation paths. This often serves as a precursor to large-scale lateral movement, credential theft, and ransomware deployment. Because it identifies high-value targets, its presence is a strong indicator of an adversary actively planning to broaden their control over the domain.

## Recommendation

Prioritize the identification and investigation of unauthorized SharpHound executions within the environment.
- Deploy the provided Sigma rule to monitor for process creation events matching the known binary attributes.
- Configure EDR solutions to log `OriginalFileName` and `process_name` fields in `Sysmon` Event ID 1 or Windows Event ID 4688.
- Hunt for historical executions by searching process telemetry for `SharpHound.exe` across the last 30 days to identify past discovery activity.
- Implement strict application whitelisting or Constrained Language Mode in PowerShell to limit the ability to execute unauthorized binaries and scripts.
