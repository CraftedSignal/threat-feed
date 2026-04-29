---
title: BRICKSTORM Malware Targeting VMware vSphere Environments
slug: 2026-04-brickstorm-vsphere
description: The BRICKSTORM malware targets VMware vSphere environments, specifically vCenter Server Appliance (VCSA) and ESXi hypervisors, by exploiting weak security configurations to establish persistence at the virtualization layer, leading to administrative control and potential data exfiltration.
date: "2026-04-02T13:55:05Z"
type: threat
types:
  - threat
severities:
  - critical
actors:
  - BRICKSTORM
tags:
  - vsphere
  - virtualization
  - brickstorm
  - persistence
  - lateral-movement
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://cloud.google.com/blog/topics/threat-intelligence/vsphere-brickstorm-defender-guide/
rules:
  - title: Detect Startup File Modification in Photon OS
    description: Detects modifications to startup files in Photon OS, commonly used for persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.004
    data_sources:
      - file_event
      - linux
  - title: Detect SSH Login without Logging
    description: Detects SSH logins to the VCSA Photon OS without corresponding command logging, which indicates suspicious administrative access.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

The BRICKSTORM campaign targets VMware vSphere environments, with a focus on the vCenter Server Appliance (VCSA) and ESXi hypervisors. This campaign, building on previous BRICKSTORM research, highlights the increasing threats targeting virtualized infrastructure. By gaining persistence at the virtualization layer, attackers bypass traditional security measures, such as endpoint detection and response (EDR) agents, which are often ineffective in these environments. The attackers exploit weak security architectures, identity design flaws, lack of host-based configuration enforcement, and limited visibility within the virtualization layer. This allows them to maintain long-term persistence and gain administrative control over the entire vSphere environment, making the VCSA a prime target due to its centralized control. This activity is not due to vendor vulnerabilities but rather misconfigurations and security gaps. vSphere 7 reached End of Life (EoL) in October 2025, so organizations using this version are at increased risk.

## Attack Chain

1. **Initial Access:** The attacker gains initial access to the vSphere environment, potentially through compromised credentials or vulnerabilities in externally facing services.
2. **VCSA Compromise:** The attacker targets the vCenter Server Appliance (VCSA) to gain centralized control over the vSphere environment.
3. **Privilege Escalation:** The attacker escalates privileges within the VCSA to gain root or administrative access to the underlying Photon Linux OS.
4. **Persistence:** The attacker establishes persistence by modifying system files or creating malicious services that survive reboots. This may involve writing scripts to `/etc/rc.local.d` or modifying startup files.
5. **Lateral Movement:** The attacker uses the compromised VCSA to move laterally to other ESXi hosts and virtual machines within the environment.
6. **Data Access:** The attacker accesses the underlying storage (VMDKs) of virtual machines, bypassing operating system permissions and traditional file system security, to exfiltrate sensitive data.
7. **Control of ESXi Hosts:** The attacker resets root credentials on any managed ESXi host, providing full control of the hypervisor.
8. **Impact:** The attacker can power off, delete, or reconfigure any virtual machine, encrypt datastores, disable virtual networks, and exfiltrate data. The ultimate objective could be data theft, disruption of services, or ransomware deployment.

## Impact

A successful BRICKSTORM attack can have severe consequences, including complete compromise of the vSphere environment. This can lead to data exfiltration of Tier-0 assets, disruption of critical services (such as domain controllers), and potential ransomware deployment across all virtual machines. Organizations may face significant financial losses, reputational damage, and legal liabilities. The lack of command-line logging on the Photon OS shell further hinders incident response efforts.

## Recommendation

*   Harden the vCenter Server Appliance (VCSA) by implementing the security configurations recommended in the Mandiant vCenter Hardening Script (reference: vCenter Hardening Script link in Overview).
*   Implement logging and monitoring for the Photon OS shell to detect unauthorized access and command execution (reference: Phase 4 in Content).
*   Upgrade to a supported version of vSphere to receive critical security patches (reference: vSphere 7 End of Life in Content).
*   Enable Secure Boot, strictly firewall management interfaces, and disable shell access on ESXi hosts and the VCSA (reference: Technical Hardening in Content).
*   Deploy the Sigma rule to detect modifications to startup files for persistence on Photon OS (reference: Sigma rule: "Detect Startup File Modification in Photon OS").
