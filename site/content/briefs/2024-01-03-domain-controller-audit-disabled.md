---
title: Windows AD Domain Controller Audit Policy Disabled
slug: 2024-01-03-domain-controller-audit-disabled
description: Detection of disabled audit policies on a Windows domain controller by monitoring Windows Security Event Logs for EventCode 4719, indicative of an attacker attempting to evade detection and potentially leading to data theft, privilege escalation, and full network compromise.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - windows
vendors:
  - Microsoft
  - Splunk
products:
  - Windows Event Log Security
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4719
rules:
  - title: Detect Audit Policy Changes on Domain Controllers
    description: Detects changes to audit policies on domain controllers using Windows Event ID 4719, indicating potential attacker activity to evade detection.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Audit Policy Changes via AuditPID
    description: Detects audit policy modifications by looking for changes to AuditPID values.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

This detection identifies the disabling of audit policies on a Windows Active Directory domain controller, a critical security event that can signify malicious activity. The detection uses Windows Security Event Logs, specifically EventCode 4719, to monitor for changes where success or failure auditing is removed. Attackers often disable audit policies to evade detection after gaining unauthorized access to a domain controller. This activity can be a precursor to more severe attacks, including data theft, privilege escalation, and full network compromise. The analytic leverages a Splunk search query designed to identify alterations to audit policies and provide context through lookups to identify the specific policies affected. The original Splunk detection was published on 2026-05-05.

## Attack Chain

1. **Initial Access:** An attacker gains unauthorized access to a domain controller, often through credential theft or exploiting a vulnerability.
2. **Privilege Escalation:** The attacker escalates their privileges to a level sufficient to modify audit policies, such as through exploiting a privilege escalation vulnerability or using compromised administrator credentials.
3. **Discovery:** The attacker performs reconnaissance to identify existing audit policies and their configurations.
4. **Disable Auditing:** The attacker disables specific audit policies on the domain controller using tools native to the operating system or by directly modifying Group Policy Objects (GPOs). This action generates Windows Security Event Log 4719.
5. **Evasion:** By disabling auditing, the attacker attempts to evade detection by security monitoring tools and personnel.
6. **Lateral Movement/Data Theft/Privilege Escalation:** With auditing disabled, the attacker can now perform lateral movement, data theft, or further privilege escalation without generating the usual audit logs that would alert defenders.
7. **Persistence:** The attacker establishes persistence mechanisms to maintain access to the compromised domain controller, such as creating rogue accounts or modifying system configurations.

## Impact

Successful disabling of audit policies on a domain controller can have severe consequences. It allows attackers to operate undetected within the network, potentially leading to data theft, privilege escalation, and complete network compromise. Without proper auditing, security teams lose visibility into malicious activities, making incident response and forensic investigations significantly more difficult. The impact is magnified by the central role domain controllers play in network authentication and authorization.

## Recommendation

*   Enable and monitor Windows Security Event Log EventCode 4719 on all domain controllers (reference: Overview).
*   Deploy the Sigma rule provided in this brief to your SIEM and tune it for your environment (reference: Sigma rule).
*   Investigate any instances of EventCode 4719 where audit policies are disabled on domain controllers to determine the source and intent of the change (reference: Overview).
