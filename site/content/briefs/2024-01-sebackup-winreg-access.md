---
title: Suspicious Remote Registry Access via SeBackupPrivilege
slug: 2024-01-sebackup-winreg-access
description: Detection of remote registry access by an account with SeBackupPrivilege, potentially indicating credential exfiltration attempts via SAM registry hive dumping.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - lateral-movement
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
references:
  - https://github.com/mpgn/BackupOperatorToDA
  - https://raw.githubusercontent.com/Wh04m1001/Random/main/BackupOperators.cpp
  - https://www.elastic.co/security-labs/detect-credential-access
rules:
  - title: Suspicious Remote Registry Access via SeBackupPrivilege
    description: Detects remote access to the registry by an account with SeBackupPrivilege, potentially indicating credential dumping attempts.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - lateral_movement
    techniques:
      - T1003
      - T1021.002
    data_sources:
      - network_connection
      - windows
  - title: SeBackupPrivilege Enabled Logon
    description: Detects a logon event where SeBackupPrivilege is enabled, which could be a precursor to credential dumping.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies suspicious activity related to credential access on Windows systems. Specifically, it focuses on scenarios where an account with the SeBackupPrivilege (typically associated with the Backup Operators group) remotely accesses the Windows Registry. Attackers can leverage this privilege to bypass access controls and dump the Security Account Manager (SAM) registry hive, which stores password hashes. This activity often precedes credential access and privilege escalation attempts, where the attacker aims to extract sensitive information from the dumped SAM hive to gain unauthorized access to other systems or elevate their privileges within the network. The detection logic looks for a sequence of events: first, a special logon event indicating the use of SeBackupPrivilege, followed by a network share access event targeting the "winreg" share.

## Attack Chain

1.  **Initial Access:** The attacker gains initial access to a system, potentially through phishing, exploiting a vulnerability, or using stolen credentials.
2.  **Privilege Escalation:** The attacker attempts to escalate privileges on the compromised system. If the initial access does not grant SeBackupPrivilege, they may exploit vulnerabilities or misconfigurations to gain membership in the Backup Operators group or otherwise acquire the necessary privilege.
3.  **Special Logon:** The attacker logs in using an account with the SeBackupPrivilege. This triggers a "logged-in-special" event (Event ID 4672) with the SeBackupPrivilege listed.
4.  **Remote Registry Access:** The attacker uses remote administration tools or scripts to access the registry of a target system remotely, specifically targeting the "winreg" share. This triggers a file share access event (Event ID 5145).
5.  **SAM Hive Dump:** The attacker uses the SeBackupPrivilege to bypass access controls and copies the SAM registry hive (or portions thereof) to a location accessible to them.
6.  **Credential Extraction:** The attacker extracts password hashes from the dumped SAM hive using tools like Mimikatz or other offline password cracking utilities.
7.  **Lateral Movement:** The attacker uses the extracted credentials to move laterally to other systems within the network, gaining access to additional resources and expanding their foothold.
8.  **Goal Completion:** The attacker achieves their final objective, such as data exfiltration, ransomware deployment, or disruption of services.

## Impact

Successful exploitation can lead to the compromise of domain credentials and widespread lateral movement within the network. This could enable attackers to access sensitive data, disrupt critical services, or deploy ransomware, resulting in significant financial losses and reputational damage. Given the sensitivity of the SAM hive, even a single successful compromise can have far-reaching consequences. The impact is especially high in environments with a large number of systems sharing the same domain, as the attacker can potentially compromise a significant portion of the infrastructure.

## Recommendation

*   Enable both "Audit Detailed File Share" and "Audit Special Logon" Windows audit policies to generate the necessary events for detection, as mentioned in the setup section of the original rule.
*   Deploy the provided Sigma rules to your SIEM to detect suspicious remote registry access attempts utilizing SeBackupPrivilege, and tune them for your environment.
*   Review and restrict the use of SeBackupPrivilege to only those accounts that absolutely require it for legitimate backup operations, minimizing the potential attack surface.
*   Investigate any alerts generated by these detections promptly to determine the scope of the compromise and take appropriate remediation steps.
*   Monitor for Event ID 5145 with RelativeTargetName containing "winreg" along with Event ID 4672 with SeBackupPrivilege to identify potential credential access attempts (see the original rule's `query` field).
