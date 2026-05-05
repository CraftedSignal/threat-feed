---
title: ESXi Audit Tampering Detection
slug: 2024-01-esxi-audit-tampering
description: Detection identifies the use of the esxcli system auditrecords commands to tamper with logging on an ESXi host, potentially evading detection and hindering forensic analysis.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vmware
  - esxi
  - audit-tampering
  - defense-evasion
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
    technique_id: T1070
    technique_name: Indicator Removal on Host
references:
  - https://detect.fyi/detecting-and-responding-to-esxi-compromise-with-splunk-f33998ce7823
rules:
  - title: ESXi Audit Tampering Detection
    description: Detects the use of esxcli system auditrecords command to tamper with logging on an ESXi host.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1070
    data_sources:
      - syslog
      - vmware
  - title: ESXi Audit Records Access via Shell
    description: Detects the use of esxcli system auditrecords command through a shell session.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1070
    data_sources:
      - syslog
      - vmware
rules_count: 2
---

This detection identifies attempts to tamper with audit records on VMware ESXi hosts. Attackers with administrative privileges on an ESXi host can use the `esxcli system auditrecords` command to modify or delete audit logs. This can be done either remotely or locally on the host, and is indicative of an attacker attempting to cover their tracks, evade detection, and hinder subsequent forensic investigations. Successfully tampering with audit logs allows malicious actors to operate undetected within the environment, potentially leading to long-term compromise and data exfiltration. This activity is particularly relevant in cases involving ransomware, such as Black Basta, where attackers may attempt to erase evidence of their lateral movement and payload deployment.

## Attack Chain

1. An attacker gains initial access to a system with privileges to access the ESXi host.
2. The attacker authenticates to the ESXi host, either locally or remotely, likely using compromised credentials.
3. The attacker executes the `esxcli system auditrecords` command.
4. The command is used with parameters to modify existing audit records, such as deleting entries or changing timestamps.
5. The attacker may target specific log entries related to their activities to erase evidence.
6. After tampering, the attacker continues their malicious activities (e.g., lateral movement, data exfiltration, or ransomware deployment) with reduced risk of detection.
7. The absence of relevant audit logs impairs incident response and forensic analysis efforts.

## Impact

Successful tampering of ESXi audit records can severely hinder incident response and forensic analysis. Without accurate logs, security teams will struggle to determine the scope and timeline of an attack. In environments affected by ransomware like Black Basta, this can lead to delayed containment and increased data loss. The blurring of the attack timeline prevents recovery and remediation efforts. While there are no victim statistics available for this specific technique, the impact on affected organizations can be significant, resulting in financial losses, reputational damage, and regulatory fines.

## Recommendation

*   Enable Syslog on all ESXi hosts and forward logs to a centralized logging server to ensure logs are captured and retained even if local logs are tampered with.
*   Deploy the Sigma rule "ESXi Audit Tampering Detection" to your SIEM to detect the usage of `esxcli system auditrecords` command.
*   Investigate any alerts triggered by the Sigma rule, focusing on the source and destination of the command execution.
*   Monitor the risk score associated with the impacted systems using the `risk_objects` field in the report.
*   Review access controls and privileges assigned to ESXi hosts to minimize the attack surface.
