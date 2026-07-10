---
title: ESXi Audit Tampering via esxcli
slug: 2024-01-03-esxi-audit-tampering
description: Attackers use esxcli system auditrecords commands on ESXi hosts to tamper with logging, hindering forensic analysis and detection efforts, potentially leading to prolonged compromise and data breaches.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - esxi
  - audit-tampering
  - defense-evasion
  - vmware
vendors:
  - VMware
products:
  - ESXi
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1070
    technique_name: Indicator Removal on Host
references:
  - https://detect.fyi/detecting-and-responding-to-esxi-compromise-with-splunk-f33998ce7823
rules:
  - title: Detect ESXi Audit Tampering via esxcli
    description: Detects the execution of esxcli commands used to tamper with ESXi audit records, potentially indicating an attempt to evade detection or hinder forensic analysis.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.003
    data_sources:
      - syslog
      - vmware
  - title: Detect ESXi Audit Tampering with Remote Option
    description: Detects the usage of `esxcli system auditrecords` with the `remote` option, potentially indicating an attempt to tamper with remote logging.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.003
    data_sources:
      - syslog
      - vmware
  - title: Detect ESXi Audit Tampering with Local Option
    description: Detects the usage of `esxcli system auditrecords` with the `local` option, potentially indicating an attempt to tamper with local logging.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.003
    data_sources:
      - syslog
      - vmware
rules_count: 3
---

This threat brief addresses the detection of audit tampering activities on VMware ESXi hosts. The attack involves the use of `esxcli system auditrecords` commands to manipulate or delete audit logs. This activity is typically conducted by attackers who have already gained unauthorized access to the ESXi host and are attempting to cover their tracks, evade detection, and maintain persistence. The primary objective of this activity is to prevent the recording of system-level audit events, thereby hindering forensic analysis and incident response efforts. This technique can be used in conjunction with ransomware attacks like Black Basta to maximize dwell time and impact.

## Attack Chain

1.  The attacker gains unauthorized access to the ESXi host, possibly through exploiting vulnerabilities or using compromised credentials.
2.  The attacker executes esxcli commands to interact with the ESXi host's system.
3.  The attacker utilizes the `esxcli system auditrecords` command to manipulate audit logging configurations.
4.  The attacker uses the remote option with the `esxcli system auditrecords` command.
5.  The attacker uses the local option with the `esxcli system auditrecords` command.
6.  The attacker modifies the log retention policies or removes existing log entries to erase evidence of malicious activity.
7.  The attacker continues with other malicious activities, such as deploying ransomware or exfiltrating sensitive data, with a reduced risk of detection.
8.  The attacker achieves their final objective, such as data encryption or exfiltration, while remaining undetected due to the compromised audit logs.

## Impact

Compromised ESXi hosts can lead to significant disruptions and data loss. Organizations that rely on virtualization technologies may experience widespread service outages, as ESXi hosts are critical components of the infrastructure. The tampering of audit logs makes incident response and forensic analysis extremely difficult, potentially allowing attackers to maintain persistence and carry out further malicious activities undetected. In cases where ransomware is involved, successful audit tampering can result in delayed detection, prolonged encryption, and significant financial losses due to downtime and recovery efforts.

## Recommendation

*   Configure ESXi systems to forward syslog output to a centralized logging server (SIEM) and ensure proper parsing using the appropriate Splunk Technology Add-on for VMware ESXi Logs as mentioned in the [Splunk documentation](https://detect.fyi/detecting-and-responding-to-esxi-compromise-with-splunk-f33998ce7823).
*   Deploy the provided Sigma rule to detect the execution of `esxcli system auditrecords` commands on ESXi hosts.
*   Investigate any alerts triggered by the Sigma rule, focusing on identifying the user, source IP address (`dest` field), and the specific commands executed.
*   Enable Sysmon process creation logging on Windows-based management systems used to administer ESXi hosts to identify potential credential theft or lateral movement.
