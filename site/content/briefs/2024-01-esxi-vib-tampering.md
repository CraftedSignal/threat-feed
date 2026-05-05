---
title: ESXi VIB Acceptance Level Tampering Detection
slug: 2024-01-esxi-vib-tampering
description: This detection identifies changes to the VIB (vSphere Installation Bundle) acceptance level on an ESXi host, potentially allowing the installation of unsigned or unverified software and lowering the system's integrity enforcement.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vmware
  - esxi
  - vib
  - tampering
  - post-compromise
  - ransomware
vendors:
  - VMware
  - Splunk
products:
  - ESXi
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
references:
  - https://github.com/splunk/security_content/blob/main/detections/application/esxi_vib_acceptance_level_tampering.yml
rules:
  - title: ESXi VIB Acceptance Level Tampering
    description: Detects changes to the VIB acceptance level on an ESXi host using esxcli.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - syslog
      - vmware
  - title: Suspicious ESXi VIB Installation
    description: Detects VIB installation events from non-standard locations on ESXi hosts.
    platform: sigma
    severity: medium
    tactics:
      - installation
    data_sources:
      - syslog
      - vmware
rules_count: 2
---

This threat brief focuses on detecting tampering with the vSphere Installation Bundle (VIB) acceptance level on ESXi hosts. Attackers may attempt to modify the VIB acceptance level, typically using the `esxcli software acceptance set` command, to bypass security controls and install malicious or unsigned software. The default acceptance levels ensure that only VMware-approved or trusted vendor-signed packages are installed, maintaining system integrity. By lowering this level, for example, to "CommunitySupported", an attacker can introduce unsigned VIBs, potentially leading to persistent compromise, data exfiltration, or disruption of virtualized workloads. This activity is often observed post-compromise.

## Attack Chain

1.  Initial access to the ESXi host is gained through an exploit or stolen credentials.
2.  The attacker elevates privileges to execute commands with `shell` access.
3.  The attacker uses the `esxcli software acceptance set` command to modify the VIB acceptance level, potentially setting it to `CommunitySupported` to allow unsigned VIBs.
4.  The attacker installs a malicious VIB package onto the ESXi host.
5.  The malicious VIB executes its payload, which could include installing a backdoor, modifying system configurations, or stealing data.
6.  The attacker attempts to maintain persistence by hiding the malicious VIB or creating scheduled tasks.
7.  The attacker leverages the compromised ESXi host to move laterally within the virtualized environment, targeting other virtual machines.
8.  The attacker achieves their final objective, such as deploying ransomware or exfiltrating sensitive data from the virtualized environment.

## Impact

Successful modification of the VIB acceptance level can lead to the installation of malicious software on ESXi hosts, resulting in the compromise of virtual machines and the entire virtualized infrastructure. This can lead to data breaches, system instability, and significant operational disruption. The Black Basta ransomware group has been known to target ESXi environments, highlighting the importance of detecting this type of activity.

## Recommendation

*   Enable ESXi syslog forwarding to a central log management system to capture relevant events (data_source: "VMWare ESXi Syslog").
*   Deploy the Sigma rule `ESXi VIB Acceptance Level Tampering` to detect changes to the VIB acceptance level (rule: "ESXi VIB Acceptance Level Tampering").
*   Monitor ESXi hosts for unusual process execution and file modifications, especially related to VIB installation (rule: "Suspicious ESXi VIB Installation").
*   Investigate any instances of the `esxcli software acceptance set` command being used (rule: "ESXi VIB Acceptance Level Tampering").
