---
title: ESXi Account Modification Detection
slug: 2024-01-esxi-account-modified
description: Detection of local user account creation, deletion, or modification on an ESXi host, potentially indicating unauthorized access, persistence attempts, or defense evasion.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - esxi
  - vmware
  - account-management
  - persistence
  - privilege-escalation
vendors:
  - VMware
products:
  - ESXi
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
references:
  - https://detect.fyi/detecting-and-responding-to-esxi-compromise-with-splunk-f33998ce7823
rules:
  - title: ESXi Account Modified via esxcli
    description: Detects ESXi account modification via esxcli command.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098
    data_sources:
      - syslog
      - vmware
  - title: ESXi Account Deletion via esxcli
    description: Detects ESXi account deletion via esxcli command.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1098
    data_sources:
      - syslog
      - vmware
rules_count: 2
---

This detection identifies the creation, deletion, or modification of local user accounts on VMware ESXi hosts. This activity can be indicative of various malicious actions, including unauthorized access by threat actors, attempts to remove indicators of compromise, or the establishment of persistence mechanisms to maintain control over the compromised host. This type of activity is particularly concerning as ESXi hosts are critical components of virtualized environments, and their compromise can lead to significant impact. This detection leverages ESXi syslog data. It is important to note that ESXi account modifications are rare in most environments, making this a high-fidelity indicator of potentially malicious activity. The detection logic requires the appropriate Splunk Technology Add-on for VMware ESXi Logs for proper field extraction and CIM compatibility.

## Attack Chain

1.  **Initial Access:** An attacker gains initial access to the ESXi host, potentially through exploiting vulnerabilities, brute-forcing credentials, or leveraging compromised credentials (T1078).
2.  **Privilege Escalation:** The attacker escalates their privileges to gain administrative or root access on the ESXi host.
3.  **Account Discovery:** The attacker enumerates existing user accounts on the ESXi host to identify potential targets or existing administrative accounts.
4.  **Account Modification:** The attacker modifies an existing user account's attributes, such as password, privileges, or SSH keys, to gain persistent access or impersonate legitimate users (T1098). The attacker may use esxcli command line interface.
5.  **New Account Creation:** The attacker creates a new local user account on the ESXi host to establish a persistent backdoor for future access (T1136.001).
6.  **Credential Access:** The attacker attempts to harvest credentials stored on the ESXi host or within the virtualized environment.
7.  **Defense Evasion:** The attacker deletes or modifies existing user accounts to remove traces of their activity or disable security measures.
8.  **Lateral Movement/Impact:** The attacker leverages their access to the ESXi host to move laterally within the virtualized environment, compromise virtual machines, or disrupt services.

## Impact

Compromise of an ESXi host can lead to the compromise of all virtual machines hosted on that server. This can result in data theft, disruption of critical services, or deployment of ransomware within the virtualized environment. Successful account modification can allow attackers to maintain persistent access to the ESXi host, even after patches are applied or other security measures are implemented. The Black Basta ransomware group, among others, has been known to target ESXi infrastructure.

## Recommendation

*   Configure ESXi hosts to forward syslog output to a centralized logging system (e.g., Splunk) as outlined in the "how_to_implement" section.
*   Deploy the Sigma rule `ESXi Account Modified via esxcli` to detect account modifications performed through the esxcli command-line interface.
*   Deploy the Sigma rule `ESXi Account Deletion via esxcli` to detect account deletions performed through the esxcli command-line interface.
*   Investigate any alerts generated by these rules to determine the legitimacy of the account modification activity.
*   Monitor ESXi host logs for unusual command-line activity, specifically commands related to account management.
