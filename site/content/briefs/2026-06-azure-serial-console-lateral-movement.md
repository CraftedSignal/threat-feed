---
title: Azure VM Serial Console Exploitation for Lateral Movement
slug: 2026-06-azure-serial-console-lateral-movement
description: Adversaries with privileged Azure RBAC roles are exploiting the Azure VM Serial Console to gain SYSTEM/root access on virtual machines, bypassing network controls like NSGs and JIT policies, with detections focusing on unusual user and source network combinations.
date: "2026-06-18T18:42:34Z"
type: threat
types:
  - threat
severities:
  - medium
tags:
  - cloud
  - azure
  - lateral-movement
  - defense-evasion
  - initial-access
  - vm
vendors:
  - Microsoft
products:
  - Azure Virtual Machine
  - Azure Serial Console
affected_os:
  - Windows
  - Linux
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/serial-console-overview
  - https://blog.pwnedlabs.io/diving-deep-into-azure-vm-attack-vectors
  - https://www.netspi.com/blog/technical-blog/adversary-simulation/7-ways-to-execute-command-on-azure-virtual-machine-virtual-machine-scale-sets/
rules:
  - title: Azure VM Serial Console Connection
    description: Detects successful connections to the Azure VM Serial Console, which can bypass NSGs and JIT access. Anomalous connections from unusual users or ASNs require immediate investigation.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - lateral_movement
    techniques:
      - T1021.008
    data_sources:
      - cloud
      - azure
  - title: Azure RBAC Role Assignment for Virtual Machine Contributor
    description: Detects the assignment of the 'Virtual Machine Contributor' role or similar roles providing extensive control over VMs, a prerequisite for Serial Console exploitation.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1078.004
      - T1136.003
    data_sources:
      - cloud
      - azure
  - title: Azure VM Boot Diagnostics Enabled
    description: Detects when Boot Diagnostics is enabled on an Azure Virtual Machine, a prerequisite for using the Serial Console.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1526
    data_sources:
      - cloud
      - azure
rules_count: 3
---

This brief details the threat of adversaries leveraging the Azure VM Serial Console for unauthorized access and lateral movement within Azure environments. The Serial Console provides text-based console access to a virtual machine (VM) via its boot diagnostics serial port, operating independently of the VM's network state. This out-of-band access mechanism allows attackers to bypass crucial network security controls, including Network Security Groups (NSGs) and Just-in-Time (JIT) access policies. An adversary possessing a privileged Azure Role-Based Access Control (RBAC) role, such as Virtual Machine Contributor, and targeting a VM with enabled boot diagnostics, can exploit this capability to obtain interactive sessions with SYSTEM (Windows) or root (Linux) privileges. Detection strategies focus on identifying anomalous connections by monitoring for unobserved combinations of user identities and source Autonomous System Numbers (ASNs) connecting to the Serial Console, indicative of potential malicious activity.

## Attack Chain

1.  Adversary gains initial access to Azure credentials, potentially through phishing, compromised identity, or misconfigured service principal.
2.  Adversary identifies target Azure Virtual Machines within their accessible scope that have boot diagnostics enabled.
3.  Adversary identifies or establishes sufficient Azure RBAC permissions (e.g., Virtual Machine Contributor) on the target VM or its containing resource group/subscription.
4.  Adversary initiates a connection to the Azure VM Serial Console for the chosen target VM.
5.  The Serial Console connection is successfully established, effectively bypassing any configured Network Security Groups (NSGs) or Just-in-Time (JIT) access policies.
6.  Adversary gains an interactive session with SYSTEM (on Windows VMs) or root (on Linux VMs) privileges.
7.  Adversary performs host-based reconnaissance, establishes persistence, deploys additional malware, or exfiltrates sensitive data from the compromised VM.
8.  Adversary uses the compromised VM as a pivot point for lateral movement to other resources within the Azure environment.

## Impact

Successful exploitation of the Azure VM Serial Console by an adversary results in full SYSTEM or root-level compromise of the targeted virtual machine. This bypasses critical network security controls, allowing unauthorized interactive access to a VM even if it's isolated or unreachable via standard network protocols. The impact includes potential data exfiltration, deployment of malicious payloads (e.g., ransomware, backdoors), establishment of persistence, and lateral movement throughout the victim's Azure infrastructure, leading to broader organizational compromise and significant operational disruption. While specific victim counts are not provided in the source, any organization leveraging Azure VMs with vulnerable configurations and exposed privileged credentials is at risk.

## Recommendation

*   Deploy the provided Sigma rules for "Azure VM Serial Console Connection" and "Azure RBAC Role Assignment" to your SIEM system.
*   Enable comprehensive Azure Activity Log auditing for `MICROSOFT.SERIALCONSOLE/SERIALPORTS/CONNECT/ACTION` and `MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE` operations.
*   Baseline legitimate Serial Console usage by authorized administrators and their known source ASNs and principal IDs to reduce false positives for the "Azure VM Serial Console Connection" rule.
*   Review all high-risk alerts from the "Azure VM Serial Console Connection" rule by investigating `azure.activitylogs.identity.authorization.evidence.principal_id` and `source.as.organization.name`.
*   Implement strong Conditional Access policies and Multi-Factor Authentication (MFA) for all Azure administrative roles to mitigate initial access attempts.
*   Periodically review and prune Azure RBAC role assignments, especially for high-privilege roles like 'Virtual Machine Contributor', for the "Azure RBAC Role Assignment for Virtual Machine Contributor" rule.
*   Disable the subscription-level Serial Console where it is not operationally required to reduce attack surface.
