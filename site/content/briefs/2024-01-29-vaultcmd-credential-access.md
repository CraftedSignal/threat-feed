---
title: VaultCmd Usage for Listing Windows Credentials
slug: 2024-01-29-vaultcmd-credential-access
description: Adversaries may use vaultcmd.exe to list credentials stored in the Windows Credential Manager to gain unauthorized access to saved usernames and passwords, potentially in preparation for lateral movement.
date: "2024-01-29T12:00:00Z"
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
  - Elastic
  - Microsoft
  - SentinelOne
  - Crowdstrike
products:
  - Microsoft Defender XDR
  - Elastic Defend
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16
  - https://web.archive.org/web/20201004080456/https://rastamouse.me/blog/rdp-jump-boxes/
  - https://www.elastic.co/security-labs/detect-credential-access
rules:
  - title: Detect VaultCmd Credential Listing
    description: Detects the execution of vaultcmd.exe with arguments used to list credentials from the Windows Credential Manager.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555.004
    data_sources:
      - process_creation
      - windows
  - title: Detect VaultCmd Credential Listing (Alternative)
    description: Detects the execution of vaultcmd.exe with arguments used to list credentials from the Windows Credential Manager (alternative rule).
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may abuse the Windows Credential Manager to list or dump credentials stored within. This allows for the exfiltration of saved usernames and passwords. The tool vaultcmd.exe can be used to interact with the Credential Manager and list the stored credentials. This activity is often performed in preparation for lateral movement within a compromised network. This detection focuses on identifying instances where vaultcmd.exe is executed with the `/list*` argument, indicating an attempt to enumerate stored credentials. The detection rule is designed to identify abuse of vaultcmd for credential access, enabling defenders to detect unauthorized credential access activities.

## Attack Chain

1. An attacker gains initial access to a Windows system through various means (e.g., phishing, exploitation of a vulnerability).
2. The attacker executes `vaultcmd.exe` with the `/list` argument to enumerate the credentials stored in the Windows Credential Manager.
3. The `vaultcmd.exe` process accesses the Credential Manager to retrieve the list of saved credentials.
4. The output of `vaultcmd.exe` (the list of credentials) is captured or redirected to a file for later exfiltration.
5. The attacker parses the output to identify valuable credentials, such as domain administrator accounts or service accounts.
6. The attacker uses the acquired credentials to authenticate to other systems on the network (lateral movement).
7. The attacker elevates privileges on the target systems.
8. The final objective is achieved, such as data theft or ransomware deployment.

## Impact

Successful execution of this attack chain can lead to unauthorized access to sensitive resources, lateral movement within the network, and ultimately, data theft, system compromise, or ransomware deployment. A compromised user account can grant the attacker access to internal systems, confidential data, and critical infrastructure. If the attacker gains domain administrator credentials, they can compromise the entire Windows domain.

## Recommendation

*   Monitor process execution events for instances of `vaultcmd.exe` being executed with the `/list*` argument (Data Source: Windows Security Event Logs, Sysmon, Microsoft Defender XDR, SentinelOne, Crowdstrike).
*   Deploy the Sigma rule "Detect VaultCmd Credential Listing" to your SIEM to identify potential credential access attempts.
*   Investigate any identified instances of `vaultcmd.exe` being executed with the `/list*` argument to determine the legitimacy of the activity.
*   Review and update endpoint protection configurations to ensure that similar threats are detected and blocked in the future.
