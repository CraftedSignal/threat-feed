---
title: ESXi VM Discovery via ESXCLI Commands
slug: 2024-01-02-esxi-vm-discovery
description: Adversaries may use ESXCLI commands to discover virtual machines on an ESXi host, potentially indicating reconnaissance for high-value targets, environment mapping, or preparation for data theft or destructive operations.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - esxi
  - vmware
  - discovery
vendors:
  - VMware
products:
  - VMware ESXi
references:
  - https://github.com/splunk/security_content/blob/main/detections/application/esxi_vm_discovery.yml
rules:
  - title: ESXi VM Discovery
    description: Detects the use of ESXCLI commands to list virtual machines on an ESXi host.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    data_sources:
      - syslog
      - vmware
  - title: ESXi VM Discovery with User Context
    description: Detects ESXCLI VM discovery commands with user context from ESXi logs.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    data_sources:
      - syslog
      - vmware
rules_count: 2
---

The detection focuses on identifying the execution of ESXCLI commands specifically used for virtual machine discovery within a VMware ESXi environment. While legitimate administrators utilize these commands for troubleshooting and management, their presence can also signal malicious reconnaissance activities by threat actors. This reconnaissance could be aimed at identifying critical VMs, mapping the virtual infrastructure, or laying the groundwork for subsequent attacks like data exfiltration or ransomware deployment. This activity is particularly relevant to organizations heavily reliant on virtualization.

## Attack Chain

1.  **Initial Access:** The attacker gains initial access to the ESXi host, potentially through credential compromise, exploiting a vulnerability, or social engineering.
2.  **Authentication:** The attacker authenticates to the ESXi host, possibly using stolen credentials or a compromised account.
3.  **Command Execution:** The attacker executes ESXCLI commands to list virtual machines. This involves commands containing "esxcli vm process" and "list".
4.  **Data Collection:** The ESXi host processes the ESXCLI command, retrieving information about the virtual machines running on the host.
5.  **Reconnaissance:** The attacker analyzes the output of the ESXCLI command to identify high-value targets, map the virtual environment, and plan further actions.
6.  **Lateral Movement (Potential):** Based on the gathered information, the attacker may attempt to move laterally to other systems within the virtual environment.
7.  **Data Theft/Destructive Operations (Potential):** The attacker may attempt to steal sensitive data from the targeted virtual machines or perform destructive actions, such as encrypting or deleting data.

## Impact

Successful execution of ESXCLI commands for VM discovery can provide attackers with a comprehensive understanding of the virtual infrastructure. This knowledge can be leveraged to identify critical assets, facilitate lateral movement, and ultimately lead to data theft, system disruption, or ransomware deployment. Depending on the scope and sensitivity of the compromised VMs, the impact could range from business disruption to significant financial losses.

## Recommendation

*   Enable VMWare ESXi Syslog and ingest into your SIEM to detect malicious activity.
*   Deploy the Sigma rule "ESXi VM Discovery" to your SIEM and tune for your environment to detect suspicious ESXCLI command usage.
*   Investigate any detected instances of ESXCLI commands being used for VM discovery, especially when originating from non-administrative accounts.
*   Monitor user accounts, especially those with elevated privileges, for suspicious behavior.
