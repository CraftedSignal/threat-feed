---
title: Windows Audit Policy Security Descriptor Tampering via Auditpol
slug: 2024-01-auditpol-security-descriptor-tampering
description: Detection of `auditpol.exe` execution with arguments to modify the audit policy security descriptor, indicative of defense evasion by adversaries aiming to limit audit logging.
date: "2024-01-02T12:00:00Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - auditpol
  - security descriptor
  - defense evasion
  - windows
vendors:
  - Microsoft
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-set
rules:
  - title: Auditpol Security Descriptor Modification
    description: Detects the execution of auditpol.exe with arguments to modify security descriptors, indicative of defense evasion.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.002
    data_sources:
      - process_creation
      - windows
  - title: Auditpol Disable Audit Category
    description: Detects the execution of auditpol.exe with arguments to disable logging of an audit category.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This brief focuses on the misuse of `auditpol.exe` to tamper with Windows audit policy security descriptors. Attackers, including red teams, may leverage this technique to evade defenses by limiting the scope and effectiveness of audit logging. By modifying the security descriptor of the audit policy, adversaries can restrict access and prevent certain users or applications from reverting unauthorized changes. This activity is typically executed after disabling specific policy categories from logging. The modification aims to weaken security monitoring, thereby facilitating further malicious operations without raising immediate alarms. The successful execution of this tampering could lead to full machine compromise or lateral movement, as attackers operate with reduced visibility.

## Attack Chain

1.  Initial access is achieved through existing system privileges or exploitation of a vulnerability.
2.  The attacker disables specific audit policy categories using `auditpol.exe` to reduce the volume of logged events.
3.  `auditpol.exe` is executed with the `/set` flag and `/sd` parameter to modify the security descriptor of the audit policy.
4.  The modified security descriptor restricts access to the audit policy, preventing certain users or applications from reverting the changes.
5.  The attacker leverages the reduced audit visibility to perform reconnaissance activities, such as discovering credentials or mapping the network.
6.  Malicious tools, like custom scripts or malware, are deployed and executed without triggering audit-based alerts.
7.  Lateral movement is initiated to compromise other systems within the network, expanding the attacker's footprint.
8.  The attacker achieves their final objective, which may include data exfiltration, ransomware deployment, or long-term persistence.

## Impact

Successful tampering of the audit policy security descriptor can lead to a significant reduction in security visibility. This can allow attackers to operate undetected for extended periods, increasing the likelihood of successful data breaches, ransomware attacks, or other malicious activities. While the exact number of victims and sectors targeted is not specified, the potential impact is widespread across any organization relying on Windows audit logging for security monitoring. A successful attack can result in substantial financial losses, reputational damage, and regulatory penalties.

## Recommendation

*   Deploy the Sigma rule `Auditpol Security Descriptor Modification` to your SIEM to detect the use of `auditpol.exe` with arguments indicative of security descriptor tampering.
*   Enable Sysmon Event ID 1 process creation logging to provide the necessary data for the Sigma rule to function effectively.
*   Investigate any instances of `auditpol.exe` execution with the `/set` and `/sd` flags, as these are rarely legitimate in normal system administration.
*   Regularly review and validate the integrity of Windows audit policies to ensure they have not been tampered with.
*   Implement strict access controls for `auditpol.exe` to prevent unauthorized users from modifying audit policies.
*   Use a host-based intrusion detection system (HIDS) to monitor for unauthorized modifications to the audit policy security descriptor.
