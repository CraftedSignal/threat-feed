---
title: Windows Account Discovery of Administrator Accounts
slug: 2024-01-admin-recon
description: Adversaries may execute the `net.exe` or `wmic.exe` commands to enumerate administrator accounts or groups, both locally and within the domain, to gather information for follow-on actions.
date: "2024-01-03T17:14:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - discovery
  - account-discovery
  - windows
vendors:
  - Microsoft
  - Crowdstrike
  - Elastic
products:
  - M365 Defender
  - Elastic Defend
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1069
    technique_name: Permission Groups Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1069
    technique_name: Permission Groups Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
references:
  - https://attack.mitre.org/techniques/T1069/
  - https://attack.mitre.org/techniques/T1069/001/
  - https://attack.mitre.org/techniques/T1069/002/
  - https://attack.mitre.org/techniques/T1087/
  - https://attack.mitre.org/techniques/T1087/001/
  - https://attack.mitre.org/techniques/T1087/002/
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/discovery_admin_recon.toml
rules:
  - title: Detect net.exe Enumerating Administrator Accounts
    description: Detects the use of net.exe to enumerate administrator-related groups and users.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1069.002
      - T1087.002
    data_sources:
      - process_creation
      - windows
  - title: Detect wmic.exe Enumerating Administrator Accounts
    description: Detects the use of wmic.exe to enumerate administrator-related groups and users.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1069.002
      - T1087.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers often perform reconnaissance activities within a compromised environment to understand the available resources and potential targets. This reconnaissance helps them plan subsequent actions, such as privilege escalation and lateral movement. This activity involves using built-in Windows utilities like `net.exe` and `wmic.exe` to enumerate administrator-related user accounts and groups. This information can reveal potential targets for credential compromise or other post-exploitation activities. Lower privileged accounts commonly perform this enumeration.

## Attack Chain

1.  The attacker gains initial access to a Windows system.
2.  The attacker executes `net.exe` with arguments to list users and groups.
3.  The attacker filters the output for administrator-related keywords like "admin", "Domain Admins", "Enterprise Admins", "Remote Desktop Users", or "Organization Management".
4.  Alternatively, the attacker executes `wmic.exe` to query user accounts.
5.  The attacker parses the output from `wmic.exe` to identify administrator accounts.
6.  The attacker identifies privileged accounts to target for credential theft or privilege escalation.
7.  The attacker uses the identified accounts to perform lateral movement or access sensitive data.

## Impact

Successful enumeration of administrator accounts allows an attacker to identify high-value targets within the environment. This can lead to credential theft, privilege escalation, lateral movement, and ultimately, unauthorized access to sensitive data or systems. While the risk score is low, this activity serves as a precursor to more serious compromises.

## Recommendation

*   Monitor process creation events for `net.exe` and `wmic.exe` commands with arguments related to user and group enumeration using the Sigma rules provided.
*   Investigate any instances of lower-privileged accounts executing these commands and filter out authorized administrative accounts performing the same actions.
*   Enable Windows process creation logging to capture the necessary events.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
