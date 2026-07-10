---
title: Volume Shadow Copy Deletion via WMIC
slug: 2024-01-03-volume-shadow-copy-deletion-wmic
description: Attackers use Windows Management Instrumentation Command-line (WMIC) to delete volume shadow copies, inhibiting system recovery in ransomware and destructive attacks.
date: "2024-01-03T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - volume-shadow-copy
  - wmic
  - ransomware
  - impact
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1047
    technique_name: Windows Management Instrumentation
references:
  - https://attack.mitre.org/techniques/T1490/
  - https://attack.mitre.org/techniques/T1047/
rules:
  - title: Detect Volume Shadow Copy Deletion via WMIC
    description: Detects the execution of wmic.exe with arguments used to delete volume shadow copies, commonly associated with ransomware attacks.
    platform: sigma
    severity: high
    tactics:
      - execution
      - impact
    techniques:
      - T1047
      - T1490
    data_sources:
      - process_creation
      - windows
  - title: Detect WMIC process executing with original filename
    description: Detects the execution of processes with a file name that is commonly renamed to avoid detection, but the original file name is wmic.exe
    platform: sigma
    severity: high
    tactics:
      - execution
      - impact
    techniques:
      - T1047
      - T1490
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers frequently delete Volume Shadow Copies (VSS) using Windows Management Instrumentation Command-line (WMIC) to hinder system recovery. This tactic is observed in ransomware and other destructive attacks. By removing shadow copies, attackers aim to eliminate restoration options for victims, increasing the likelihood of ransom payment. Detecting and preventing unauthorized shadow copy deletion is crucial for maintaining data integrity and system resilience. This activity is typically observed on Windows endpoints and servers.

## Attack Chain

1.  Initial Access: The attacker gains access to the target system through various means, such as exploiting vulnerabilities, phishing, or using stolen credentials.
2.  Privilege Escalation (if necessary): The attacker escalates privileges to obtain the necessary permissions to execute commands that can modify system settings and delete shadow copies.
3.  Command Execution: The attacker executes `wmic.exe` with specific arguments to interact with VSS.
4.  Shadow Copy Enumeration (Optional): The attacker may enumerate existing shadow copies using WMIC to verify their presence before deletion.
5.  Shadow Copy Deletion: The attacker uses the `shadowcopy` alias with the `delete` parameter in WMIC to remove volume shadow copies. For example, `wmic shadowcopy delete`.
6.  Verification (Optional): The attacker may attempt to verify the successful deletion of shadow copies.
7.  Data Encryption (Typical): In ransomware scenarios, the attacker proceeds to encrypt data on the system after deleting the shadow copies to maximize impact.
8.  Demand Ransom: The attacker demands ransom payment in exchange for the decryption key, leaving victims with limited recovery options due to the deleted shadow copies.

## Impact

Successful deletion of volume shadow copies significantly hinders or completely prevents system recovery without external backups. This tactic is often observed in ransomware attacks, where victims are forced to pay ransom to recover their encrypted data. The impact can range from temporary disruption of services to permanent data loss, depending on the availability of alternative backup solutions.

## Recommendation

*   Deploy the Sigma rule "Detect Volume Shadow Copy Deletion via WMIC" to detect the execution of `wmic.exe` with shadow copy deletion arguments in your SIEM.
*   Enable process creation logging on Windows endpoints using Sysmon to capture the necessary events for the provided Sigma rules.
*   Monitor process execution for commands containing "wmic" and "shadowcopy delete" to identify potential shadow copy deletion attempts.
*   Review and restrict the accounts authorized to perform shadow copy deletion operations to minimize the risk of unauthorized modifications.
