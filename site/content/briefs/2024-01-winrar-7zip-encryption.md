---
title: WinRAR and 7-Zip Encryption Abuse for Data Exfiltration Preparation
slug: 2024-01-winrar-7zip-encryption
description: Adversaries use WinRAR or 7-Zip to create encrypted archives in preparation for data exfiltration, using command-line arguments to enable encryption functionality.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - data-exfiltration
  - archive
  - encryption
  - windows
vendors:
  - WinRAR
  - 7-Zip
products:
  - WinRAR
  - 7-Zip
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1560
    technique_name: Archive Collected Data
references:
  - https://www.welivesecurity.com/2020/12/02/turla-crutch-keeping-back-door-open/
  - https://www.elastic.co/security-labs/siestagraph-new-implant-uncovered-in-asean-member-foreign-ministry
  - https://attack.mitre.org/techniques/T1005/
  - https://attack.mitre.org/techniques/T1560/
  - https://attack.mitre.org/techniques/T1560/001/
rules:
  - title: WinRAR Encrypted Archive Creation
    description: Detects the creation of encrypted archives using WinRAR with password protection.
    platform: sigma
    severity: medium
    tactics:
      - collection
    techniques:
      - T1560.001
    data_sources:
      - process_creation
      - windows
  - title: 7-Zip Encrypted Archive Creation
    description: Detects the creation of encrypted archives using 7-Zip with password protection.
    platform: sigma
    severity: medium
    tactics:
      - collection
    techniques:
      - T1560.001
    data_sources:
      - process_creation
      - windows
  - title: WinRAR and 7-Zip archive exclusion path
    description: Excludes common parent paths to avoid false positives
    platform: sigma
    severity: informational
    tactics:
      - collection
    techniques:
      - T1560.001
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

Attackers often compress and encrypt data collected from compromised systems prior to exfiltration. This compression helps to stage and obfuscate the content, potentially reducing the amount of data transferred over the network. Encryption further conceals the archive's contents, making the activity less conspicuous during security reviews. This behavior is often observed in the later stages of an intrusion, indicating that the attacker has already gained access, collected data, and is preparing to move it offsite. The use of WinRAR and 7-Zip, common archiving tools, allows for easy packaging and encryption. This activity is detected by monitoring process execution for specific command-line arguments used to initiate archive creation with encryption.

## Attack Chain

1.  The attacker gains initial access to the target system (e.g., through phishing or exploiting a vulnerability).
2.  The attacker performs reconnaissance to identify valuable data for exfiltration (T1005 - Data from Local System).
3.  The attacker stages the collected data in a temporary directory on the compromised host.
4.  The attacker executes WinRAR or 7-Zip with command-line arguments to create a password-protected archive (T1560.001 - Archive via Utility). This includes parameters such as `-hp`, `-p`, `/hp`, or `/p` for WinRAR, and `-p` for 7-Zip.
5.  The encrypted archive is created in a staging location, potentially within a user's profile or a public folder.
6.  The attacker may transfer the archive off-host using various methods, such as browser uploads, cloud synchronization clients, RMM tools, or SMB to unusual destinations.
7.  The attacker deletes the original data from the compromised host to remove traces of the data collection.
8.  The attacker successfully exfiltrates the data.

## Impact

Successful execution of this attack chain leads to the exfiltration of sensitive data. The impact can range from exposure of personally identifiable information (PII) to theft of confidential business data, depending on the nature of the compromised data. Organizations in any sector are potentially vulnerable, as the technique is applicable across various environments where sensitive data is stored. The number of affected systems and the volume of exfiltrated data will vary depending on the scope of the compromise and the attacker's objectives.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM to detect WinRAR/7-Zip encryption activity and tune for your environment.
*   Review process ancestry for archiving commands to identify the launching process and validate its legitimacy as described in the "Triage and Analysis" section of the brief.
*   Monitor for archives being created in unusual locations or with suspicious naming patterns.
*   Investigate related activity on the same host/user, such as credential access attempts, discovery actions, lateral movement, and outbound network transfers, over the past 48 hours as described in the "Triage and Analysis" section of the brief.
*   Enable Sysmon process creation logging to activate the rules above.
