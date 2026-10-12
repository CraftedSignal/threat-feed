---
title: Credential Dumping via Copy Command from Shadow Copy
slug: 2026-10-credential-dumping-shadow-copy
description: Attackers frequently utilize the copy command to extract sensitive Windows credential files from Volume Shadow Copies to enable offline password cracking and privilege escalation.
date: "2026-10-12T17:38:34Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - privilege-escalation
  - windows-security
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
    evidence: The following analytic detects the use of the copy command to dump credentials from a shadow copy.
    confidence_band: high
rules:
  - title: Detect Credential Dumping via Copy Command
    description: Detects the use of the copy command to dump credentials from a shadow copy by monitoring command lines referencing SAM, SECURITY, SYSTEM, or NTDS.dit files.
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
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Implement Sigma rule in SIEM to alert on copy command usage against sensitive hives.
      owner: Detection Engineering
      due: 48h
      evidence: Analytic rule provided in source.
  hunt_leads:
    - lead: Search for instances of vssadmin creating shadows followed by copy commands.
      technique_id: T1003.003
      data_needed:
        - Process creation events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Common TTP sequence for credential dumping.
  mitigation_plan:
    - priority: medium_term
      action: Restrict administrative access to shadow copy management tools.
      owner: IT Operations
      addresses: T1003.003
      evidence: Reducing surface area for VSS interaction.
---

This threat involves the unauthorized access and exfiltration of critical Windows authentication artifacts, including the SAM, SECURITY, and SYSTEM registry hives, as well as the Active Directory database file (ntds.dit). Adversaries leverage Volume Shadow Copy (VSS) to bypass file locks that typically prevent direct access to these files while the system is running. Once the volume shadow copy is mounted or accessed, the attacker uses standard administrative utilities like 'copy' or 'robocopy' to duplicate these files to a secondary location for offline processing. This technique is a cornerstone of credential harvesting and often precedes lateral movement or domain-wide compromise. Detecting this behavior requires visibility into granular process command-line arguments that reference sensitive system file paths.

## Attack Chain

1. Attacker gains initial access or code execution on the target Windows system.
2. Attacker checks for administrative privileges required to interact with Volume Shadow Copies.
3. Attacker executes 'vssadmin' or 'wmic' to create a shadow copy of the target system volume.
4. Attacker identifies the path to the shadow copy of the volume containing system files (e.g., C:\\Windows\\System32\\config\\).
5. Attacker executes a command-line tool (e.g., cmd.exe, copy, robocopy) to copy sensitive files (sam, security, system, ntds.dit) from the shadow copy mount to a staging directory.
6. Attacker compresses or archives the staged files to facilitate exfiltration or further processing.
7. Attacker exfiltrates the archived files to an external C2 server or secondary staging system.
8. Attacker performs offline cracking of hashes extracted from the dumped files to escalate privileges or move laterally.

## Impact

Successful execution of this attack grants adversaries access to local and domain-level authentication hashes. This allows for offline brute-force or dictionary attacks, resulting in the compromise of user and service accounts. Once decrypted, these credentials enable attackers to escalate privileges to Domain Admin level, maintain persistent access, and conduct broad data exfiltration across the organization.

## Recommendation

Prioritize the implementation of process-level command-line monitoring to detect unauthorized attempts to access critical system files via Volume Shadow Copy.

* Deploy the provided Sigma rule to your SIEM to monitor for 'copy' command executions involving 'sam', 'security', 'system', or 'ntds.dit' file paths.
* Enable Sysmon Event ID 1 (Process Creation) and ensure command-line logging is fully captured to facilitate detection of these artifacts.
* Use the Splunk Common Information Model (CIM) to map process execution logs to the Endpoint data model to ensure detection logic functions correctly.
* Audit administrative access to the 'vssadmin' binary and restrict its use to authorized system management service accounts.
