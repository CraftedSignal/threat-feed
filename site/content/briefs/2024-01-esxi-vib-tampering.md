---
title: ESXi VIB Acceptance Level Tampering
slug: 2024-01-esxi-vib-tampering
description: Attackers modify the ESXi VIB acceptance level to install unsigned or unverified software, weakening the host's integrity enforcement.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - esxi
  - vib
  - tampering
  - vmware
vendors:
  - VMware
products:
  - ESXi
  - vSphere
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://github.com/splunk/security_content/blob/main/detections/application/esxi_vib_acceptance_level_tampering.yml
rules:
  - title: ESXi VIB Acceptance Level Tampering
    description: Detects changes to the ESXi VIB acceptance level using esxcli.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562
    data_sources:
      - syslog
      - vmware
  - title: ESXi VIB Installation from Unknown Source
    description: Detects installation of VIBs from non-VMware sources after acceptance level has been changed.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562
    data_sources:
      - syslog
      - vmware
rules_count: 2
---

This brief focuses on detecting the modification of the VIB (vSphere Installation Bundle) acceptance level on ESXi hosts. Attackers can leverage this technique to weaken the system's security posture. Specifically, changing the acceptance level to "CommunitySupported" or similar settings reduces the enforcement of integrity checks, allowing for the installation of potentially malicious or unverified software. While the original Splunk detection was published in 2026, this activity remains relevant in current environments. This activity is commonly associated with post-compromise activity during ransomware attacks such as Black Basta, or associated with threat groups such as China-Nexus.

## Attack Chain

1.  The attacker gains initial access to the ESXi host, potentially through compromised credentials or exploiting vulnerabilities in vSphere services.
2.  The attacker executes commands via the ESXi shell to modify the VIB acceptance level. This often involves using the `esxcli software acceptance set` command.
3.  The attacker changes the VIB acceptance level to a less restrictive setting, such as "CommunitySupported" or "AcceptanceLevelUnset".
4.  The ESXi host's integrity checks are effectively weakened, allowing for the installation of unsigned or unverified VIBs.
5.  The attacker installs a malicious VIB containing backdoors, rootkits, or other malicious payloads, such as custom scripts or binaries.
6.  The malicious VIB is loaded and executed by the ESXi host, providing the attacker with persistent access or the ability to perform malicious actions.
7.  The attacker may use this access to move laterally within the virtualized environment, compromise other virtual machines, or exfiltrate sensitive data.
8.  The final objective is often data encryption for ransom, data exfiltration, or disruption of services within the targeted environment.

## Impact

Compromising the VIB acceptance level allows attackers to install malicious software on ESXi hosts. This can lead to complete host compromise, lateral movement within the virtualized environment, data theft, or ransomware deployment. Organizations in various sectors, including finance, healthcare, and critical infrastructure, are potentially at risk. Successful exploitation can result in significant financial losses, reputational damage, and disruption of critical services.

## Recommendation

*   Configure ESXi hosts to forward syslog output to a central log management system for monitoring (VMWare ESXi Syslog).
*   Deploy the provided Sigma rule `ESXi VIB Acceptance Level Tampering` to detect modifications to the VIB acceptance level.
*   Investigate any detected changes to the VIB acceptance level, focusing on the user and source of the command.
*   Review and harden ESXi host access controls and credential management practices to prevent unauthorized access.
*   Monitor for the installation of unsigned or unverified VIBs on ESXi hosts.
