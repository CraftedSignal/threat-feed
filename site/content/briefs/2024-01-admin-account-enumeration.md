---
title: Windows Account Discovery of Administrator Accounts
slug: 2024-01-admin-account-enumeration
description: The rule identifies instances of lower privilege accounts enumerating Administrator accounts or groups using built-in Windows tools like net.exe and wmic.exe, potentially indicating reconnaissance activity by an attacker after initial compromise.
date: "2024-01-29T18:29:00Z"
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
products:
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
  - https://attack.mitre.org/techniques/T1087/
rules:
  - title: Detect Net.exe Enumerating Administrator Accounts
    description: Detects the use of net.exe to enumerate administrator accounts and groups.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1069
      - T1087
    data_sources:
      - process_creation
      - windows
  - title: Detect WMIC Enumerating User Accounts
    description: Detects the use of wmic.exe to enumerate user accounts.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1069
      - T1087
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

After gaining initial access to a Windows environment, attackers often perform reconnaissance to gather information about the network, users, and systems. This activity helps them understand the environment and plan further actions, such as privilege escalation or lateral movement. One common reconnaissance technique involves enumerating administrator accounts and groups to identify potential targets for credential compromise or other post-exploitation activities. The native Windows utilities `net.exe` and `wmic.exe` are often used for this purpose. This activity is often performed by lower-privileged accounts to avoid detection. This activity is detectable across endpoint, system, and M365 Defender data sources.

## Attack Chain

1. An attacker gains initial access to a Windows system via an exploit or stolen credentials.
2. The attacker executes `net.exe` with arguments such as `group`, `user`, or `localgroup` to enumerate user accounts and groups.
3. The `net.exe` commands include search terms like "*admin*", "Domain Admins", "Remote Desktop Users", "Enterprise Admins", or "Organization Management" to specifically target administrator accounts.
4. Alternatively, the attacker executes `wmic.exe` with arguments such as `group` or `useraccount` to gather the same information.
5. The attacker parses the output of these commands to identify privileged accounts and group memberships.
6. This information is used to identify targets for credential theft, such as Kerberoasting or password spraying.
7. The attacker attempts to compromise identified administrator accounts.
8. Upon successful compromise, the attacker uses the elevated privileges to achieve their final objective, such as data exfiltration or ransomware deployment.

## Impact

Successful enumeration of administrator accounts allows attackers to identify high-value targets within the network. This can lead to the compromise of critical systems, data breaches, and significant operational disruption. Although this rule is low severity, this discovery tactic is a key step in a wider attack chain that often leads to much more severe impacts.

## Recommendation

*   Enable Windows Security Event Logging and ensure proper collection of process creation events to facilitate detection of the described behavior (Data Source: Windows Security Event Logs).
*   Deploy the Sigma rules provided below to your SIEM and tune the rules based on your environment to reduce false positives.
*   Review and harden account permissions, focusing on limiting membership in highly privileged groups such as Domain Admins (T1069).
*   Investigate any instances of non-administrator accounts enumerating administrative accounts or groups (see rule "Enumeration of Administrator Accounts").
