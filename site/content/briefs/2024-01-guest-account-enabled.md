---
title: Windows Guest Account Enabled via net.exe
slug: 2024-01-guest-account-enabled
description: The Windows guest account, typically restricted, can be enabled via `net.exe` for malicious activities like malware installation or data theft, potentially indicating persistence, defense evasion, privilege escalation or initial access.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - guest-account
  - persistence
  - windows
vendors:
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_guest_account_enabled_via_net_exe.yml
rules:
  - title: Detect Guest Account Enabled via Net.EXE
    description: Detects when the Windows guest account is enabled via net.exe
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1078.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Guest Account Enabled via PowerShell
    description: Detects when the Windows guest account is enabled via PowerShell
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1078.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Windows guest account, when enabled, bypasses standard security controls, providing attackers with a foothold for unauthorized actions. Default guest accounts have limited privileges but enabling them can facilitate unauthorized access. Using `net.exe` to activate the guest account is a common technique. Although legitimate administrative use of the guest account exists for temporary access or troubleshooting, malicious actors can leverage it for persistence, defense evasion, privilege escalation, and initial access. This detection focuses on identifying instances of `net.exe` being used to enable the guest account, allowing for timely investigation of potentially malicious activity. This activity can be used by attackers of all types.

## Attack Chain

1.  An attacker gains initial access to the system through existing credentials or exploits.
2.  The attacker executes `net.exe` with administrative privileges.
3.  The `net user guest /active:yes` command is executed to enable the guest account.
4.  The attacker uses the newly enabled guest account to log in.
5.  The attacker attempts to install malware, exfiltrate data, or perform other malicious activities.
6.  The attacker uses the guest account to move laterally within the network, potentially compromising other systems.
7.  The attacker leverages the guest account for persistence, maintaining unauthorized access even after the initial compromise is remediated.

## Impact

Successful exploitation leads to unauthorized access to the compromised system via the enabled guest account. Attackers can leverage this access to install malware, steal sensitive data, or perform other malicious activities, potentially leading to data breaches, financial losses, and reputational damage. The enabled guest account can also facilitate lateral movement within the network, increasing the scope of the attack. The severity depends on the permissions assigned and the data accessible to the guest account.

## Recommendation

*   Enable Sysmon EventID 1 and Windows Event Log Security 4688 logging to detect the execution of `net.exe` (data_source).
*   Deploy the Sigma rule `Detect Guest Account Enabled via Net.EXE` to your SIEM to identify suspicious guest account activation attempts (rules).
*   Filter out legitimate activations by authorized IT or support teams related to maintenance activities to reduce false positives (known_false_positives).
*   Investigate all instances of guest account activation using the provided drilldown searches to determine if malicious activity occurred (drilldown_searches).
*   Monitor the `dest` and `parent_process_name` fields as potential risk and threat objects, respectively (rba).
