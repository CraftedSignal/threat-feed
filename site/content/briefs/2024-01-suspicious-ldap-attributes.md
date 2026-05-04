---
title: Suspicious Access to LDAP Attributes
slug: 2024-01-suspicious-ldap-attributes
description: The rule detects suspicious access to LDAP attributes in Active Directory by identifying read access to a high number of Active Directory object attributes, which can help adversaries find vulnerabilities, elevate privileges, or collect sensitive information.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - active_directory
  - ldap
  - discovery
  - windows
vendors:
  - Microsoft
products:
  - Active Directory
affected_os:
  - Windows
mitre_ttps:
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
    technique_id: T1482
    technique_name: Domain Trust Discovery
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/discovery_high_number_ad_properties.toml
  - https://attack.mitre.org/techniques/T1069/
  - https://attack.mitre.org/techniques/T1069/002/
  - https://attack.mitre.org/techniques/T1087/
  - https://attack.mitre.org/techniques/T1087/002/
  - https://attack.mitre.org/techniques/T1482/
rules:
  - title: Suspicious Access to LDAP Attributes
    description: Detects suspicious access to LDAP attributes by monitoring for event ID 4662 with a high number of accessed properties.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1087.002
    data_sources:
      - process_creation
      - windows
  - title: Suspicious LDAP Read Property Access
    description: Detects suspicious read access to LDAP attributes by monitoring for event ID 4662 where AccessMaskDescription equals Read Property
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1087.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This rule identifies read access to a high number of Active Directory object attributes, which can help adversaries find vulnerabilities, elevate privileges, or collect sensitive information. The rule focuses on event code 4662, filtering for 'Read Property' access where the number of properties accessed is greater than or equal to 2000. The rule is designed to detect potential reconnaissance activities within an Active Directory environment, providing security teams with insights into unusual access patterns that may indicate malicious intent. This detection logic helps security teams proactively identify and respond to potential threats targeting Active Directory environments.

## Attack Chain

1.  The attacker gains initial access to a system within the target network, possibly through compromised credentials or a phishing attack (not directly covered in the provided source).
2.  The attacker uses the compromised account to query Active Directory via LDAP.
3.  The attacker issues a series of LDAP queries, requesting a large number of attributes for various Active Directory objects, triggering event ID 4662.
4.  The event logs record the excessive number of read property accesses (winlog.event_data.Properties), exceeding the threshold of 2000.
5.  The attacker analyzes the gathered information to identify potential targets, such as privileged accounts, sensitive data stores, or vulnerable systems.
6.  The attacker attempts to elevate privileges by exploiting identified vulnerabilities or misconfigurations within Active Directory.
7.  The attacker uses the elevated privileges to access sensitive information or move laterally within the network.
8.  The attacker achieves their objective, such as data exfiltration or system compromise.

## Impact

Successful exploitation allows attackers to gather sensitive information about the Active Directory environment, identify potential vulnerabilities, elevate privileges, and move laterally within the network. This can lead to data breaches, system compromise, and significant disruption to business operations. The number of victims and sectors targeted are dependent on the scope and objectives of the attacker.

## Recommendation

*   Enable Audit Directory Service Access to generate the necessary events (event code 4662) as mentioned in the setup instructions.
*   Deploy the Sigma rule "Suspicious Access to LDAP Attributes" to your SIEM and tune the threshold (length(winlog.event_data.Properties) >= 2000) for your environment.
*   Review event logs for event code 4662, focusing on the `winlog.event_data.Properties` field, to understand which attributes were accessed.
*   Investigate the source machine from which the LDAP queries originated by examining the `winlog.event_data.SubjectUserSid` field.
