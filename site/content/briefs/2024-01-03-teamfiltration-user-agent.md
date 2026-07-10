---
title: TeamFiltration Tool User-Agent Detected in Entra ID Sign-ins
slug: 2024-01-03-teamfiltration-user-agent
description: The TeamFiltration tool, used for Entra ID and Microsoft 365 enumeration and password spraying, is detected via specific user-agent strings in sign-in logs.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azure
  - o365
  - teamfiltration
  - credential-access
vendors:
  - Microsoft
products:
  - Microsoft Entra ID
  - Microsoft 365
  - Microsoft Teams
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1069
    technique_name: Permission Groups Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1201
    technique_name: Password Policy Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1526
    technique_name: Cloud Service Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1580
    technique_name: Cloud Infrastructure Discovery
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
references:
  - https://www.proofpoint.com/us/blog/threat-insight/attackers-unleash-teamfiltration-account-takeover-campaign
  - https://github.com/Flangvik/TeamFiltration
iocs:
  - type: domain
    value: github.com
ioc_counts:
  domain: 1
rules:
  - title: Entra ID Sign-in TeamFiltration User-Agent Detected
    description: Detects sign-in attempts using the TeamFiltration tool based on the user-agent string.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - discovery
    techniques:
      - T1069.003
      - T1110.003
    data_sources:
      - network_connection
      - azure
  - title: Entra ID Sign-in TeamFiltration Electron User-Agent Detected
    description: Detects sign-in attempts using TeamFiltration tool via electron user-agent in Azure signin logs.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - discovery
    techniques:
      - T1069.003
      - T1110.003
    data_sources:
      - network_connection
      - azure
rules_count: 2
---

The TeamFiltration tool is an open-source utility designed for enumeration, password spraying, and exfiltration within Entra ID and Microsoft 365 environments. Active threat actors leverage TeamFiltration to discover users, groups, and roles, and to execute password spraying attacks targeting Microsoft Entra ID and Microsoft 365 accounts. This detection focuses on identifying TeamFiltration usage by monitoring for its specific user-agent strings within Azure and Microsoft 365 sign-in logs. This activity began being tracked in July 2025. TeamFiltration uses a list of FOCI compliant applications to perform enumeration and password spraying. TeamFiltration uses Microsoft Teams client ID `1fec8e78-bce4-4aaf-ab1b-5451cc387264` for enumeration.

## Attack Chain

1.  Initial Access: The attacker gains initial access or leverages existing compromised credentials.
2.  Tool Execution: The attacker executes the TeamFiltration tool on a compromised system or from a cloud-based instance.
3.  Enumeration: TeamFiltration uses the Microsoft Teams client ID `1fec8e78-bce4-4aaf-ab1b-5451cc387264` to enumerate users, groups, and roles within the target Entra ID/M365 environment using Graph API requests.
4.  Password Spraying: The tool performs password spraying attacks against enumerated user accounts.
5.  Credential Access: If successful, the attacker gains access to user accounts.
6.  Privilege Escalation: The attacker attempts to escalate privileges within the environment leveraging the compromised accounts.
7.  Lateral Movement: Using compromised accounts, the attacker attempts lateral movement to gain access to additional resources.
8.  Data Exfiltration: If successful in gaining access to sensitive data, the attacker exfiltrates the data.

## Impact

Successful attacks using TeamFiltration can result in widespread unauthorized access to sensitive data within Microsoft Entra ID and Microsoft 365 environments. This can lead to data breaches, financial loss, and reputational damage. The tool is actively used in account takeover campaigns and can affect organizations of any size that utilize Entra ID and M365 services.

## Recommendation

*   Deploy the Sigma rule `Entra ID Sign-in TeamFiltration User-Agent Detected` to your SIEM to detect the use of TeamFiltration based on user-agent strings.
*   Monitor Azure and Microsoft 365 sign-in logs for user agents matching those used by TeamFiltration, as indicated in the rule above (logsource: `azure.signinlogs` or `o365.audit`).
*   Investigate any sign-in events matching the TeamFiltration user-agent, paying close attention to the source IP addresses and user accounts involved.
*   Enable Conditional Access policies to require MFA for API and CLI-based access to mitigate password spraying attacks.
