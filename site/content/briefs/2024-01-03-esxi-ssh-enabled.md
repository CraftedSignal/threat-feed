---
title: ESXi SSH Enabled Detection
slug: 2024-01-03-esxi-ssh-enabled
description: The enabling of SSH on ESXi hosts, as detected in ESXi Syslog, can signal malicious lateral movement by threat actors aiming for persistent access.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - esxi
  - ssh
  - lateral-movement
vendors:
  - VMware
products:
  - ESXi
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
references:
  - https://github.com/splunk/security_content/blob/main/detections/application/esxi_ssh_enabled.yml
rules:
  - title: ESXi SSH Enabled Detection
    description: Detects SSH being enabled on ESXi hosts via syslog messages, which may indicate unauthorized access and potential malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.004
    data_sources:
      - syslog
      - vmware
  - title: ESXi SSH Enabled - Destination Extraction
    description: Extracts the destination host from ESXi SSH enabled syslog messages.
    platform: sigma
    severity: informational
    tactics:
      - lateral_movement
    techniques:
      - T1021.004
    data_sources:
      - syslog
      - vmware
rules_count: 2
---

This detection identifies when SSH is enabled on VMware ESXi hosts. While SSH can be used legitimately for administrative purposes, its enablement can also be an early warning sign of malicious activity. Attackers might enable SSH to establish persistent remote access following a successful compromise, whether through credential theft, vulnerability exploitation, or other means. This access can then be leveraged for lateral movement, data exfiltration, or other malicious objectives, particularly in ransomware campaigns. The detection uses ESXi syslog data to identify the specific events associated with SSH enablement.

## Attack Chain

1.  Initial compromise of a host within the ESXi environment using an unpatched vulnerability or credential compromise.
2.  Establish initial foothold and perform reconnaissance of the ESXi environment.
3.  Elevate privileges on the compromised host, if necessary, to enable SSH.
4.  Enable SSH access on the ESXi host using the ESXi command-line interface or vSphere client.
5.  Attacker uses SSH to move laterally within the ESXi environment, accessing other hosts or virtual machines.
6.  Install malware or tools for data exfiltration or other malicious activities.
7.  Encrypt virtual machines and demand ransom, characteristic of ransomware attacks.
8.  Maintain persistent access through SSH to reinfect the environment after recovery attempts.

## Impact

Enabling SSH on ESXi hosts by unauthorized actors allows for lateral movement within the virtualized environment. This can lead to the compromise of critical virtual machines, data exfiltration, and potentially a complete ransomware attack. Successfully exploiting this vulnerability can result in significant financial loss, data breach, and reputational damage. The ESXi Post Compromise analytic story highlights the importance of detecting anomalous SSH activity in preventing broader compromise.

## Recommendation

*   Configure ESXi systems to forward syslog output to a SIEM to capture the required logs for detection (VMWare ESXi Syslog).
*   Deploy the Sigma rule `ESXi SSH Enabled Detection` to your SIEM and tune the filter list for false positives specific to your environment.
*   Investigate any detected SSH enablement events on ESXi hosts immediately to determine if the activity is authorized.
*   Review and enforce strict access control policies for ESXi hosts to prevent unauthorized SSH access (T1021.004).
