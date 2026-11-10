---
brief_id: brief-2026-09-suspicious-ntds-dit-exfiltration
event_id: brief-2026-09-suspicious-ntds-dit-exfiltration
revision: 2
activity_at: "2026-11-10T03:05:32Z"
revision_history:
  - revision: 2
    at: "2026-11-10T03:05:32Z"
    checksum: sha256:b4f83833f0b5341b9e8fe18f689ab3e3374b26f125f1d56d58ea5c4688a5181e
    summary: OS windows server
    changed_fields:
      - affected_os
      - affected_products
      - affected_vendors
      - lastmod
      - references
      - rules
      - ttps
      - updates
    source_urls:
      - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_susp_ntds.yml
title: Suspicious NTDS.DIT Credential Dumping Patterns
slug: 2026-09-suspicious-ntds-dit-exfiltration
description: Adversaries frequently target the NTDS.DIT database using native Windows utilities or specialized scripts to perform offline credential cracking.
date: "2026-09-03T13:47:07Z"
lastmod: "2026-11-10T03:04:52Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - credential-access
  - windows
  - ntds-dit
vendors:
  - Microsoft
products:
  - Active Directory
affected_os:
  - Windows Server
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    subtechnique_id: T1003.003
    subtechnique_name: NTDS
    evidence: The activity targets the NTDS.DIT file to extract credentials, which is the standard behavior associated with T1003.003.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_susp_ntds.yml
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
updates:
  - at: "2026-11-10T03:04:52Z"
    level: L1
    summary: OS windows server
    sources:
      - sigma-hq
    source_urls:
      - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_susp_ntds.yml
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
