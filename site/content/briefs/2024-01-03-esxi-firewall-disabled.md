---
title: ESXi Firewall Disabled
slug: 2024-01-03-esxi-firewall-disabled
description: The ESXi firewall being disabled or set to permissive mode can expose the host to unauthorized access and network-based attacks, often preceding lateral movement, data exfiltration, or malware installation.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - esxi
  - vmware
  - firewall
  - defense-evasion
vendors:
  - VMware
products:
  - ESXi
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://github.com/splunk/security_content/blob/main/detections/application/esxi_firewall_disabled.yml
rules:
  - title: ESXi Firewall Disabled via Syslog
    description: Detects when the ESXi firewall is disabled based on syslog messages.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.004
    data_sources:
      - firewall
      - vmware
  - title: ESXi Firewall Permissive Mode Detected
    description: Detects ESXi firewall modifications indicating a permissive mode configuration via syslog messages.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.004
    data_sources:
      - firewall
      - vmware
rules_count: 2
---

Attackers often disable the ESXi firewall to gain unrestricted network access to the compromised host and the broader virtualized environment. This action bypasses a critical security control, allowing for lateral movement, data exfiltration, and the deployment of malicious software. The detection focuses on identifying instances where the ESXi firewall is intentionally disabled or set to a permissive mode. This activity can stem from misconfiguration, insider threats, or malicious actors seeking to gain a foothold. Defenders must monitor for these changes using ESXi syslog data to promptly detect and respond to potential security breaches.

## Attack Chain

1. An attacker gains initial access to an ESXi host, potentially through exploiting a vulnerability or using compromised credentials.
2. The attacker authenticates to the ESXi host using valid credentials.
3. The attacker executes commands to disable the ESXi firewall. This may involve modifying firewall rules or stopping the firewall service.
4. The ESXi host logs the change in firewall status via syslog, indicating that the firewall has been disabled or set to a permissive mode.
5. With the firewall disabled, the attacker can now move laterally within the virtualized environment without network restrictions.
6. The attacker compromises other virtual machines or ESXi hosts on the network.
7. The attacker exfiltrates sensitive data from the compromised systems.
8. The attacker installs malware, such as ransomware, on the compromised systems, disrupting operations and demanding ransom payment.

## Impact

Disabling the ESXi firewall significantly increases the risk of unauthorized access and lateral movement within a virtualized environment. Successful exploitation can lead to data breaches, ransomware deployment, and widespread disruption of critical services. Organizations with poorly configured or monitored ESXi environments are particularly vulnerable. The impact can range from data loss and financial damage to reputational harm and regulatory penalties.

## Recommendation

*   Enable Syslog on VMware ESXi hosts and forward logs to a SIEM to collect the necessary data (VMWare ESXi Syslog).
*   Deploy the provided Sigma rules to detect instances of ESXi firewalls being disabled, and tune them to the specific environment to reduce false positives (Sigma rules).
*   Investigate any detected instances of ESXi firewall changes to determine the cause and scope of the potential breach.
*   Review and harden ESXi access controls, including enforcing strong passwords and multi-factor authentication to prevent unauthorized access.
