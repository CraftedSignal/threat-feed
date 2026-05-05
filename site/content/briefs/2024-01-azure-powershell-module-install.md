---
title: Suspicious Azure PowerShell Module Installation via PowerShell Script
slug: 2024-01-azure-powershell-module-install
description: Detection of Azure AD and cloud management modules installation via PowerShell Script Block Logging, potentially indicating reconnaissance, privilege escalation, or persistence operations by adversaries.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azure
  - powershell
  - module-installation
  - privilege-escalation
  - persistence
vendors:
  - Microsoft
products:
  - Azure Active Directory
  - MSOnline
  - Az.Resources
  - AADInternals
  - PowerShell
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1069.003
    technique_name: Standard Permissions Group
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136.003
    technique_name: 'Create Account: Cloud Account'
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021.007
    technique_name: 'Remote Services: Windows Remote Management'
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_azure_powershell_module_installation_via_powershell_script.yml
rules:
  - title: Detect Suspicious Azure PowerShell Module Installation
    description: Detects the installation of Azure AD and cloud management modules via PowerShell Script Block Logging, indicating potential malicious activity.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1021.007
      - T1069.003
      - T1078
      - T1098
      - T1136.003
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Azure PowerShell Module Installation via ScriptBlockText
    description: Detects the installation of Azure AD and cloud management modules via PowerShell Script Block Logging using ScriptBlockText.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1021.007
      - T1069.003
      - T1078
      - T1098
      - T1136.003
    data_sources:
      - powershell
      - windows
rules_count: 2
---

This threat brief addresses the risk associated with the unauthorized installation of Azure PowerShell modules, such as AADInternals, Az.Resources, AzureAD, and MSOnline, using PowerShell scripts. These modules are powerful tools for managing Azure Active Directory (Azure AD) and cloud resources, granting extensive access to critical objects, user accounts, service principals, and tenant configurations. Adversaries often leverage these modules post-compromise to conduct reconnaissance, escalate privileges, establish persistence, or move laterally within the Azure environment. The use of PowerShell Script Block Logging provides an opportunity to detect such malicious activity, identifying potential threats before they can significantly impact the organization. This activity is often seen after an initial foothold has been established in the environment.

## Attack Chain

1.  Initial Access: An attacker gains initial access to a Windows system through various means, such as exploiting a vulnerability or using compromised credentials.
2.  Privilege Escalation: The attacker attempts to escalate privileges on the compromised system to gain higher-level access.
3.  Execution: The attacker executes a PowerShell script designed to install specific Azure AD and cloud management modules.
4.  Module Installation: The PowerShell script utilizes the `Install-Module` cmdlet to install modules like AADInternals, Az.Resources, AzureAD, or MSOnline.
5.  Reconnaissance: After installing the modules, the attacker uses them to gather information about the Azure AD environment, including user accounts, groups, and permissions.
6.  Lateral Movement: Armed with the gathered information, the attacker attempts to move laterally within the Azure environment, targeting other systems or resources.
7.  Persistence: The attacker establishes persistence mechanisms within Azure AD to maintain access, such as creating new user accounts or modifying existing ones.

## Impact

Successful exploitation can lead to a full-scale compromise of the Azure AD environment, potentially impacting numerous users, applications, and resources. Attackers can gain unauthorized access to sensitive data, disrupt critical services, and even take complete control of the organization's cloud infrastructure. The broad access granted by these modules makes them a prime target for attackers seeking to establish a persistent foothold and conduct further malicious activities within the Azure environment. The impact can range from data breaches and financial losses to reputational damage and regulatory penalties.

## Recommendation

*   Enable PowerShell Script Block Logging (Event ID 4104) on all Windows systems to capture the execution of PowerShell scripts, enabling detection via the provided Sigma rules.
*   Deploy the provided Sigma rule `Detect Suspicious Azure PowerShell Module Installation` to identify instances of suspicious Azure PowerShell module installations, and tune it for your environment.
*   Review and audit PowerShell script execution within your environment to identify any unauthorized or suspicious activity, using process creation logs.
*   Implement strict access controls and multi-factor authentication for Azure AD accounts to prevent unauthorized access and module installations.
*   Monitor the installation of PowerShell modules across your environment, looking for unexpected installations of Azure-related modules.
