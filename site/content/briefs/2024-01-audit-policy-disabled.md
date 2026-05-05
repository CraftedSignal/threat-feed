---
title: Windows Audit Policy Disabled
slug: 2024-01-audit-policy-disabled
description: Detection of disabled important audit policies via Windows EventCode 4719, indicating potential attacker attempts to evade detection on a compromised domain controller, leading to data theft, privilege escalation, and network compromise.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - audit-policy
  - defense-evasion
  - windows
vendors:
  - Microsoft
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
references:
  - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4719
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_important_audit_policy_disabled.yml
rules:
  - title: Auditpol Execution with Disable Argument
    description: Detects the execution of auditpol.exe with arguments that disable audit settings.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
  - title: Windows Audit Policy Change via Registry Modification
    description: Detects changes to audit policy via registry modification.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - registry_set
      - windows
  - title: Detect Clearing of Windows Event Logs
    description: Detects the clearing of Windows Event Logs, a common technique used to evade detection.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.002
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

This analytic detects the disabling of important audit policies in Windows environments, using Windows Security Event Logs and EventCode 4719. The disabling of these policies is a critical indicator of potential attacker activity, as it suggests an adversary has gained unauthorized access to a domain controller and is actively trying to evade detection by tampering with audit configurations. The detection focuses on identifying changes where success or failure auditing is removed from critical policy subcategories. This activity, if confirmed as malicious, can lead to severe consequences, including data theft, privilege escalation, and ultimately, complete network compromise. Splunk Enterprise, Splunk Enterprise Security, and Splunk Cloud can be used to implement this detection.

## Attack Chain

1.  **Initial Compromise:** An attacker gains initial access to a system within the target environment, potentially through phishing or exploiting a vulnerability.
2.  **Privilege Escalation:** The attacker escalates privileges to gain administrative access to a domain controller.
3.  **Identify Audit Policies:** The attacker identifies important audit policies that are currently enabled and generating logs.
4.  **Disable Audit Policies:** The attacker disables targeted audit policies using tools like `auditpol.exe` or by directly modifying the Group Policy Objects (GPOs). This generates Windows Security Event Log 4719.
5.  **Evade Detection:** By disabling these policies, the attacker aims to prevent their malicious activities from being logged and detected.
6.  **Lateral Movement:** The attacker leverages their privileged access to move laterally across the network, compromising additional systems and resources.
7.  **Data Exfiltration/Ransomware Deployment:** The attacker exfiltrates sensitive data or deploys ransomware to encrypt critical systems.
8.  **Persistence:** The attacker establishes persistence mechanisms to maintain long-term access to the compromised environment, potentially re-enabling disabled audit policies after completing malicious activity to hide tracks.

## Impact

Successful disabling of important audit policies can have devastating consequences. Attackers can operate undetected within the environment, leading to data theft, financial losses, and reputational damage. The lack of audit logs hinders incident response efforts, making it difficult to identify the scope of the compromise and recover effectively. Affected sectors include any organization reliant on Windows Active Directory for authentication and authorization, including government, finance, healthcare, and critical infrastructure.

## Recommendation

*   Enable the audit policy subcategory "Audit Audit Policy Change" to generate EventCode 4719 in the Windows Security Event Logs.
*   Deploy the Sigma rule "Windows Important Audit Policy Disabled" to your SIEM (Splunk) and tune it for your environment.
*   Investigate any instances of EventCode 4719 where critical audit policies are disabled, focusing on the source process (`process_id`) and affected system (`dest`).
*   Review and update the `important_audit_policy_subcategory_guids` macro to accurately reflect the audit subcategories that are most important for your environment.
*   Monitor for unusual or unauthorized use of `auditpol.exe`, a command-line tool often used to manage audit policies.
*   Use the provided drilldown searches in Splunk to pivot to related risk events and detection results for further investigation.
