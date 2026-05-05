---
title: Linux Auditd Daemon (Re)Initialization Detection
slug: 2024-01-02-linux-auditd-daemon-start
description: Detection of Linux audit daemon (auditd) re-initialization events, which can indicate attempts to re-enable audit logging after evasion or restarts with modified rule sets.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - linux
  - auditd
  - anomaly
vendors:
  - Splunk
  - Red Hat
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Splunk Add-on for Unix and Linux
  - Red Hat Enterprise Linux
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/6/html/security_guide/sec-audit_record_types
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/linux_auditd_auditd_daemon_start.yml
rules:
  - title: Linux Auditd Daemon Start
    description: Detects the start of the Linux audit daemon (auditd) by identifying DAEMON_START events.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.012
    data_sources:
      - process_creation
      - linux
  - title: Detect Auditd Configuration Changes
    description: Detects changes to the auditd configuration file.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.012
    data_sources:
      - file_event
      - linux
  - title: Detect Auditctl Rule Modifications
    description: Detects usage of auditctl to modify audit rules.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.012
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

This analytic detects the (re)initialization of the Linux audit daemon (auditd) by identifying log entries of type `DAEMON_START`. This event indicates that the audit subsystem has resumed logging after being stopped or has started during system boot. While `DAEMON_START` may be expected during reboots or legitimate configuration changes, it can also signal attempts to re-enable audit logging after evasion, or restarts with modified or reduced rule sets. Monitoring this event in correlation with `DAEMON_END`, `DAEMON_ABORT`, and `auditctl` activity provides visibility into the continuity and integrity of audit logs. Frequent or unexplained `DAEMON_START` events should be investigated, especially if they are not accompanied by valid administrative or system activity. This detection is relevant for environments utilizing auditd for security monitoring and compliance.

## Attack Chain

1. An attacker gains initial access to a Linux system.
2. The attacker identifies that auditd is enabled and logging events.
3. The attacker attempts to disable auditd to evade detection, possibly using `auditctl -s disable` or similar commands.
4. After performing malicious actions, the attacker may attempt to re-enable auditd, potentially with a modified configuration to avoid logging their activities, triggering a `DAEMON_START` event.
5. The attacker modifies the audit rules to exclude specific users, processes, or file paths from being logged.
6. The attacker restarts the auditd service using `systemctl restart auditd` or a similar command, generating a `DAEMON_START` event.
7. The system resumes logging with the modified audit rules, potentially missing critical security events.

## Impact

A successful attack can lead to a compromised Linux host where malicious activities are not properly logged, hindering incident response and forensic investigations. Attackers could manipulate audit logs by stopping and restarting the service with altered configurations, reducing the effectiveness of security monitoring. The impact includes a loss of visibility into attacker actions, potentially leading to prolonged compromise and data breaches.

## Recommendation

*   Deploy the Sigma rule `Linux Auditd Daemon Start` to your SIEM and tune for your environment to detect unexpected auditd restarts.
*   Correlate `DAEMON_START` events with `DAEMON_END` and `DAEMON_ABORT` events to identify anomalies in auditd service management.
*   Monitor `auditctl` activity for unauthorized modifications to audit rules.
*   Investigate frequent or unexplained `DAEMON_START` events, especially those not accompanied by valid administrative or system activity, as highlighted in the overview.
*   Ensure proper ingestion and normalization of auditd logs using the Splunk Add-on for Unix and Linux, as mentioned in the "How to Implement" section.
