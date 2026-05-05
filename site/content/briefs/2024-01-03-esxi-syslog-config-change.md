---
title: ESXi Syslog Configuration Changes via esxcli
slug: 2024-01-03-esxi-syslog-config-change
description: Detection of ESXi syslog configuration changes via esxcli command, potentially indicating an attempt to disrupt logging and evade detection.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - esxi
  - syslog
  - vmware
  - defense-evasion
  - t1562.003
  - t1690
  - black-basta
vendors:
  - VMware
  - Splunk
products:
  - ESXi
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://github.com/splunk/security_content/blob/main/detections/application/esxi_syslog_config_change.yml
rules:
  - title: ESXi Syslog Config Change
    description: Detects changes to the ESXi syslog configuration using esxcli.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.003
    data_sources:
      - syslog
      - vmware
  - title: ESXi Syslog Config Change - Destination Modification
    description: Detects changes to the ESXi syslog configuration where the destination host is modified.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.003
    data_sources:
      - syslog
      - vmware
rules_count: 2
---

This threat brief focuses on the detection of unauthorized or malicious changes to the syslog configuration of VMware ESXi hosts. Attackers may attempt to modify syslog settings to disable or redirect logging, thereby hindering incident response and forensic analysis. The specific technique involves using the `esxcli` command-line utility, a powerful tool for managing ESXi hosts. Successful modification of the syslog configuration allows attackers to operate with reduced visibility, potentially leading to prolonged compromise and data exfiltration. This activity can be an indicator of post-compromise activity, and has been observed in association with ransomware campaigns like Black Basta.

## Attack Chain

1.  Initial access to the ESXi host is achieved via compromised credentials or exploitation of a vulnerability.
2.  The attacker authenticates to the ESXi host, potentially escalating privileges if necessary.
3.  The attacker uses `esxcli` to query the current syslog configuration to understand the existing setup.
4.  The attacker uses `esxcli` to modify the syslog configuration, potentially changing the remote host, protocol, or port.
5.  The attacker disables or redirects syslog forwarding to a malicious or attacker-controlled server.
6.  The attacker verifies the syslog configuration changes using `esxcli` or by observing the absence of logs at the original destination.
7.  The attacker proceeds with other malicious activities, such as lateral movement, data exfiltration, or ransomware deployment, with reduced risk of detection.

## Impact

Successful modification of ESXi syslog configurations can severely impair an organization's ability to detect and respond to security incidents. This can lead to delayed detection of breaches, prolonged dwell time for attackers, and increased damage from ransomware or data theft. The consequences include significant financial losses, reputational damage, and regulatory penalties. The attack is observed being utilized post-compromise, to evade detection in ransomware campaigns like Black Basta.

## Recommendation

*   Enable ESXi syslog forwarding to a centralized logging server and monitor for configuration changes as described in the overview.
*   Deploy the provided Sigma rule `ESXi Syslog Config Change` to detect unauthorized modifications to the syslog configuration (rule ID: `esxi_syslog_config_change`).
*   Implement strict access control policies for ESXi hosts and monitor for anomalous login activity to prevent initial access.
*   Review and harden ESXi host configurations according to VMware security best practices.
*   Ensure that the Splunk Technology Add-on for VMware ESXi Logs is properly configured to parse and ingest syslog data (see How To Implement).
