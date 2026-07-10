---
title: Windows Credential Manager Abuse via VaultCmd
slug: 2024-01-vaultcmd-credential-access
description: Adversaries may abuse VaultCmd to list or dump credentials stored in the Windows Credential Manager to obtain saved usernames and passwords, potentially for lateral movement.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - windows
  - vaultcmd
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
references:
  - https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16
  - https://web.archive.org/web/20201004080456/https://rastamouse.me/blog/rdp-jump-boxes/
  - https://www.elastic.co/security-labs/detect-credential-access
rules:
  - title: Detect VaultCmd Credential Listing
    description: Detects the execution of VaultCmd with the /list argument, indicating an attempt to list saved credentials.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555.004
    data_sources:
      - process_creation
      - windows
  - title: Detect VaultCmd Executing from Unusual Location
    description: Detects VaultCmd executing from non-standard paths which may indicate suspicious or malicious behavior.
    platform: sigma
    severity: low
    tactics:
      - credential_access
    techniques:
      - T1555.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Windows Credential Manager stores credentials for websites, connected applications, and networks. Attackers may abuse the VaultCmd utility to list or dump these credentials, enabling lateral movement within a network. This involves using VaultCmd with specific arguments, such as `/list`, to extract sensitive information. Detecting this activity is crucial for identifying unauthorized credential access attempts early in the attack chain. The described technique can be used to further compromise the system or move laterally within the compromised environment.

## Attack Chain

1.  An attacker gains initial access to a Windows system through various methods, such as exploiting a vulnerability or using stolen credentials.
2.  The attacker executes `vaultcmd.exe` with the `/list` argument to enumerate the credentials stored in the Windows Credential Manager.
3.  The utility retrieves a list of saved credentials, including usernames and passwords, from the credential store.
4.  The attacker parses the output of `vaultcmd.exe` to extract the relevant credential information.
5.  The attacker uses the acquired credentials to authenticate to other systems or services within the network.
6.  The attacker leverages the newly gained access to move laterally, escalating privileges and accessing sensitive data.
7.  The attacker may repeat steps 2-6 on other systems using remote execution, such as PsExec or WMI.
8.  The final objective is to exfiltrate sensitive data, deploy ransomware, or maintain long-term access to the network.

## Impact

Successful exploitation can lead to unauthorized access to sensitive data, systems, and services. Lateral movement can compromise additional systems, expanding the scope of the attack. Depending on the targeted accounts, this can lead to a full domain compromise. The severity of impact depends on the level of access afforded by the compromised credentials.

## Recommendation

*   Deploy the Sigma rule `Detect VaultCmd Credential Listing` to detect the use of VaultCmd with `/list*` arguments (see "rules" section).
*   Enable Sysmon process creation logging to activate the rules above.
*   Monitor process execution events for `vaultcmd.exe` using the `/list` argument in your SIEM.
*   Review endpoint security logs from tools like Microsoft Defender XDR or Crowdstrike for additional context or corroborating evidence of credential access attempts.
