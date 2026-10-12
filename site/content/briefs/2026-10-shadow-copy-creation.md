---
title: Detection of Shadow Copy Creation via WMIC and PowerShell
slug: 2026-10-shadow-copy-creation
description: Threat actors leverage native administrative tools such as WMIC and PowerShell to create Volume Shadow Copies, a technique used to facilitate credential dumping and offline password cracking.
date: "2026-10-12T17:38:26Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - living-off-the-land
  - windows
  - lotl
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: The following analytic detects the creation of shadow copies using 'wmic' or 'Powershell' commands, often employed for credential dumping.
    confidence_band: high
rules:
  - title: Detect Shadow Copy Creation via WMIC or PowerShell
    description: Detects the creation of shadow copies using administrative tools as a precursor to credential dumping
    platform: sigma
    severity: medium
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
    - action: Deploy Sigma rule for shadow copy creation via WMIC/PowerShell
      owner: Detection Engineering
      due: 48h
      evidence: Analytic provided in Splunk ESCU repository
  hunt_leads:
    - lead: Search for historical instances of shadow copy creation in process logs
      technique_id: T1003.003
      data_needed:
        - Process command line logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Known technique for unauthorized credential access
---

Attackers frequently utilize "Living off the Land" (LotL) techniques to conduct malicious activities without introducing custom malware. A critical component of this methodology involves the abuse of legitimate Windows utilities, specifically WMIC and PowerShell, to initiate the creation of Volume Shadow Copies. By creating these copies, attackers can bypass file system locks to access protected system files, such as the Security Account Manager (SAM) database or other sensitive configuration files. Once these files are extracted, they are often exfiltrated for offline password cracking or reconnaissance. This activity is a hallmark of credential-access phases in campaigns by various threat actors, including those attributed to Volt Typhoon, to maintain persistence or escalate privileges within a compromised environment.

## Attack Chain

1. Attacker gains initial access to a Windows endpoint.
2. Attacker performs discovery to identify target sensitive files (e.g., SAM, SYSTEM, or application databases).
3. Attacker executes "wmic shadowcopy call create" or an equivalent PowerShell cmdlet to trigger a system-wide volume snapshot.
4. The operating system creates a snapshot of the requested volume, circumventing active file locks.
5. Attacker maps or copies the target files from the shadow copy volume.
6. Attacker exfiltrates the sensitive files (e.g., via C2 channel or staging server).
7. Attacker utilizes tools such as Mimikatz or Secretsdump to extract hashes or credentials from the stolen files.
8. Attacker performs offline cracking to recover cleartext credentials.

## Impact

Successful exploitation allows attackers to bypass standard file system access controls, leading to widespread credential exposure. This enables lateral movement, privilege escalation, and persistent unauthorized access within the target network. The compromise of credentials facilitates long-term access, which is often difficult to detect once the attacker has established valid account control.

## Recommendation

* Deploy the provided Sigma rules to detect unauthorized execution of shadow copy creation commands.
* Enable process-level logging (Sysmon Event ID 1 or Windows Security Event ID 4688) to capture command-line arguments.
* Tune the detection to exclude legitimate administrative service accounts or backup software that requires shadow copy access for legitimate system maintenance.
* Audit and restrict the use of WMIC and PowerShell by non-administrative users.
