---
title: Akira Ransomware Campaign Utilizing RDP and GOST Tunneling
slug: 2026-10-akira-ransomware
description: The Akira ransomware group utilized RDP for initial access, disabled Bitdefender security services, performed credential dumping with procdump.exe, and deployed GOST tunnels for persistence before executing final file encryption.
date: "2026-10-06T18:44:50Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Akira
tags:
  - ransomware
  - akira
  - rdp
  - credential-theft
  - exfiltration
vendors:
  - Bitdefender
products:
  - Bitdefender Endpoint Security
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1133
    technique_name: External Remote Services
    evidence: An investigation into the impacted endpoint revealed that the threat actor behind the attack accessed the endpoint via Remote Desktop Protocol (RDP)
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562.001
    technique_name: 'Impair Defenses: Disable or Modify Tools'
    evidence: several Windows services associated with the antivirus application were stopped
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003.001
    technique_name: LSASS Memory
    evidence: procdump.exe was run from the C:\PerfLogs folder, presumably to perform credential theft by dumping the contents of the lsass.exe process.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
    evidence: They established persistence using a GOST (Go Simple Tunnel) tool
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1074
    technique_name: Data Staged
    evidence: deployed Rclone for data exfiltration
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
    evidence: a concurrent PowerShell command removed volume shadow copies
    confidence_band: high
references:
  - https://www.huntress.com/blog/mapping-akira-ransomware-attack
rules:
  - title: Detect Suspicious Service Control Manager Termination
    description: Detects when Bitdefender security services are manually stopped, which is a common defense evasion technique used by Akira ransomware.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review RDP access logs for unauthorized workstation usage
      owner: SOC
      due: 24h
      evidence: The threat actor accessed the impacted endpoint via Terminal Services/RDP, from a workstation not owned by the customer.
  hunt_leads:
    - lead: Search for procdump.exe execution in C:\PerfLogs
      technique_id: T1003.001
      data_needed:
        - Process creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: procdump.exe was run from the C:\PerfLogs folder
  mitigation_plan:
    - priority: immediate
      action: Disable RDP for external facing hosts and enforce MFA
      owner: IT Operations
      addresses: Initial Access T1133
      evidence: accessed the endpoint via Remote Desktop Protocol (RDP)
---

In September 2026, an organization was targeted by the Akira ransomware group. Investigations by Huntress, conducted after agent deployment, revealed that the threat actors gained initial access via Remote Desktop Protocol (RDP) from an unauthorized workstation. Upon entry, the attackers systematically disabled Bitdefender antivirus services to facilitate further movement. The threat actors subsequently used procdump.exe from the 'C:\\PerfLogs' directory to perform credential theft by dumping the 'lsass.exe' process memory. Data exfiltration was conducted using Rclone, and persistence was established approximately four hours after the start of encryption activities using a GOST (Go Simple Tunnel) tool. The final stage involved encrypting files across the environment and using PowerShell to delete volume shadow copies.

## Attack Chain

1. The attacker gained initial access to the network via Remote Desktop Protocol (RDP) using credentials from an external, unauthorized workstation.
2. The attacker accessed the Bitdefender management console and proceeded to manually stop multiple endpoint protection services, including the 'Bitdefender Endpoint Security Service'.
3. The threat actor executed 'procdump.exe' from the 'C:\\PerfLogs' folder to dump the 'lsass.exe' memory process to harvest credentials.
4. 'Rclone' was deployed and executed to facilitate the exfiltration of sensitive organizational data to attacker-controlled infrastructure.
5. The attacker utilized PowerShell to execute commands designed to remove all volume shadow copies from the endpoint, hindering recovery.
6. A GOST (Go Simple Tunnel) tool was deployed to establish a persistent network tunnel for continued access.
7. The Akira ransomware payload was executed, utilizing 'config.dll' loaded by 'svchost.exe' to initiate the mass encryption of files.

## Impact

The attack resulted in the successful encryption of organizational files and the potential exfiltration of sensitive data. Successful Akira operations typically lead to significant operational downtime, financial extortion demands, and data breach notification requirements.

## Recommendation

- Enable and monitor Windows Event Log 7036 to detect when security services (e.g., Bitdefender) are stopped unexpectedly.
- Implement strict geofencing and multi-factor authentication (MFA) for all RDP access to prevent unauthorized initial access.
- Monitor for the execution of 'procdump.exe' and similar administrative tools (e.g., comsvcs.dll via rundll32) when initiated by non-administrative users or from suspicious paths like 'C:\\PerfLogs'.
- Deploy and enforce EDR rules to block or alert on the execution of 'Rclone' and known tunneling tools like GOST in production environments.
- Restrict the ability of users and processes to modify volume shadow copies via PowerShell or 'vssadmin.exe'.
