---
title: Azure VM Extension CRUD from Unusual Source ASN
slug: 2026-06-azure-vm-extension-crud-unusual-source
description: Threat actors are performing create, read, update, or delete (CRUD) operations against Azure VM or VM Scale Set extensions (e.g., CustomScript, DSC) from an anomalous source Autonomous System (AS) number, enabling high-privilege code execution and persistence on guest operating systems (SYSTEM on Windows, root on Linux) by abusing compromised Azure identities.
date: "2026-06-19T12:48:20Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - endpoint
  - azure
  - azure-activity-logs
  - threat-detection
  - execution
  - persistence
vendors:
  - Microsoft
products:
  - Azure VM
  - Azure VM scale set
  - CustomScript
  - DSC
  - AADSSHLoginForLinux
affected_os:
  - Windows
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1651
    technique_name: Cloud Administration Command
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1037
    technique_name: Boot or Logon Initialization Scripts
references:
  - https://www.netspi.com/blog/technical-blog/adversary-simulation/7-ways-to-execute-command-on-azure-virtual-machine-virtual-machine-scale-sets/
  - https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/custom-script-windows
  - https://hackingthe.cloud/azure/run-command-abuse/
  - https://blog.pwnedlabs.io/diving-deep-into-azure-vm-attack-vectors
  - https://www.sysdig.com/blog/the-expendable-extension-name-azure-vmaccess-naming-chaos-password-resets-and-a-detection-gap
rules:
  - title: Azure VM/VMSS Extension CRUD from Non-Microsoft ASN
    description: Detects Create, Read, Update, or Delete (CRUD) operations against Azure VM or VM scale set extensions originating from Autonomous System (AS) numbers not associated with Microsoft, indicating potential unauthorized activity or compromise.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
    techniques:
      - T1037
      - T1651
    data_sources:
      - cloud
      - azure
  - title: Azure VM/VMSS Extension WRITE from Non-Microsoft ASN
    description: Detects WRITE (Create or Update) operations on Azure VM or VM Scale Set extensions from Autonomous System (AS) numbers not associated with Microsoft, indicating a high-risk activity often used for code execution or persistence.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
    techniques:
      - T1037
      - T1651
    data_sources:
      - cloud
      - azure
rules_count: 2
---

This brief details a threat identified by Elastic, focusing on the abuse of Azure Virtual Machine (VM) and VM Scale Set (VMSS) extensions. Threat actors can perform create, read, update, or delete (CRUD) operations on these extensions, such as `CustomScript` or `Desired State Configuration (DSC)`, from an unusual source Autonomous System (AS) number. These extensions execute with high privileges (SYSTEM on Windows, root on Linux) on the guest operating system, making them a prime target for initial code execution, maintaining persistence, or defense evasion. This technique allows adversaries to run arbitrary commands, install malware, or modify system configurations without direct login, leveraging compromised Azure credentials or identities. The detection specifically targets activity originating from networks not historically associated with managing a given extension resource, while excluding benign first-party Microsoft automation.

## Attack Chain

1.  **Initial Access**: Attacker obtains valid Azure credentials (e.g., user account, service principal) through methods such as phishing, credential stuffing, or exploiting a misconfiguration.
2.  **Privilege Escalation/Lateral Movement (Azure Plane)**: Attacker identifies a target Azure subscription or resource group with permissions to manage VM or VM scale set extensions.
3.  **VM Extension CRUD Operation**: Attacker uses the compromised credentials to perform a `WRITE` (create/update), `DELETE`, or `READ` operation against an Azure VM or VMSS extension. This operation originates from an AS number not typically observed for managing that specific resource.
4.  **Code Execution (Guest OS)**: If a `WRITE` operation is performed using extensions like `CustomScript` or `DSC`, the malicious script or command embedded in the extension definition is executed on the target VM's guest OS with SYSTEM (Windows) or root (Linux) privileges.
5.  **Persistence/Defense Evasion**: The executed code establishes persistence mechanisms, such as new services, scheduled tasks, or modifying existing configurations, or removes security agents to evade detection.
6.  **Internal Reconnaissance & Data Exfiltration**: With high privileges on the VM, the attacker performs internal network reconnaissance, collects sensitive data, and prepares for exfiltration to attacker-controlled infrastructure.
7.  **Impact & Follow-on Activity**: The attacker might deploy ransomware, conduct further lateral movement across the internal network, or maintain long-term access for data theft.

## Impact

Successful exploitation of Azure VM extensions grants attackers SYSTEM or root-level privileges on target virtual machines, leading to severe consequences. This can result in unauthorized code execution, installation of persistent backdoors, and the ability to disable security controls. Organizations can face significant data breaches, potential ransomware deployment, and complete compromise of critical cloud infrastructure. The impact extends to business disruption, regulatory non-compliance, and substantial financial and reputational damage. While specific victim counts are not available for this general technique, highly privileged access on cloud assets is consistently associated with the most severe incident types.

## Recommendation

- Deploy the provided Sigma rules to your SIEM, focusing on Azure Activity Logs (`category: cloud`, `product: azure`).
- Enable comprehensive logging for Azure Activity Logs across all subscriptions to capture `MICROSOFT.COMPUTE/VIRTUALMACHINES/EXTENSIONS` events.
- Implement a baseline of expected `source.as.number` values for all Azure VM/VMSS extension management activities and create an allowlist for known, legitimate ASNs (e.g., CI/CD pipelines, internal management networks).
- Review `azure.activitylogs.identity.authorization.evidence.principal_id` and `...principal_type` fields in alerts to determine the legitimacy and permissions of the principal performing the operation.
- Integrate endpoint detection and response (EDR) telemetry (e.g., `process_creation` events from `WaAppAgent.exe` or `walinuxagent`) on Azure VMs to correlate with `WRITE` extension operations for script execution.
