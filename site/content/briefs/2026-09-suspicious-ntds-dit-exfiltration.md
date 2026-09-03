---
title: Suspicious NTDS.DIT Credential Dumping Patterns
slug: 2026-09-suspicious-ntds-dit-exfiltration
description: Adversaries frequently target the NTDS.DIT database using native Windows utilities or specialized scripts to perform offline credential cracking.
date: "2026-09-03T13:47:07Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - windows
  - ntds-dit
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: The activity targets the NTDS.DIT file to extract credentials, which is the standard behavior associated with T1003.003.
    confidence_band: high
rules:
  - title: Detect Suspicious NTDS.DIT Access Patterns
    description: Detects various methods of accessing or dumping the NTDS.DIT Active Directory database file
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003.003
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
    - action: Deploy Sigma detection rule to SIEM and test in isolated environment
      owner: Detection Engineering
      due: 48h
      evidence: Sigma rule provided in brief
  hunt_leads:
    - lead: Process creations involving ntds.dit or ntdsutil in non-administrative contexts
      technique_id: T1003.003
      data_needed:
        - Process creation logs with full CommandLine
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source document identifies these as primary indicators
---

The NTDS.DIT file is the primary database for Active Directory, containing sensitive information including password hashes. Attackers commonly attempt to exfiltrate this file to perform offline credential recovery. This activity often involves native binaries like ntdsutil, which can be misused to create an Install from Media (IFM) set, or simple file system operations to copy the database file. Additionally, offensive security tools such as NTDSDumpEx or PowerShell-based scripts are frequently deployed in compromised environments. Defenders must monitor for unauthorized execution of these tools or suspicious process behavior that interacts with the NTDS.DIT file path. This intelligence covers common exfiltration patterns that detection engineers should prioritize when monitoring Windows process execution.

## Attack Chain

1. Initial access is established on a domain controller or system with sufficient privileges.
2. The attacker identifies the location of the NTDS.DIT database file (typically C:\Windows\NTDS\ntds.dit).
3. The attacker utilizes native binaries like 'ntdsutil.exe' to initiate an 'ifm' (Install from Media) operation to create a snapshot of the database.
4. Alternatively, the attacker uses the 'copy' command or PowerShell to move the database file to a staging directory.
5. Offensive scripts or specialized binaries like 'NTDSDumpEx.exe' are executed to interact with the database.
6. The system registry 'system.hiv' file is often dumped concurrently to extract the decryption keys.
7. The attacker exfiltrates the database and key files from the network for offline processing.
8. The final objective is the acquisition of domain user credentials and potential privilege escalation.

## Impact

Successful exfiltration of the NTDS.DIT database typically leads to full domain compromise, as an attacker can crack all user hashes offline without further interaction with the network. This results in broad unauthorized access to corporate resources, data exfiltration, and potential ransomware deployment.

## Recommendation

- Deploy the Sigma rule below to monitor process creation events for suspicious NTDS-related activity.
- Enable Sysmon or Windows Event ID 4688 to capture the full Command Line for processes interacting with the NTDS folder.
- Baseline administrative usage of 'ntdsutil.exe' in your environment to distinguish legitimate domain controller maintenance from malicious activity.
- Prioritize monitoring for processes executing from temporary folders (e.g., \AppData\, \Temp\) that also access the NTDS.DIT path.
