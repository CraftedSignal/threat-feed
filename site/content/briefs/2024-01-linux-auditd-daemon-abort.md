---
title: Linux Auditd Daemon Abort Detection
slug: 2024-01-linux-auditd-daemon-abort
description: Detection of abnormal Linux audit daemon (auditd) termination via DAEMON_ABORT events, indicating potential auditing subsystem failure due to resource exhaustion, corruption, or malicious interference.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - auditd
  - linux
  - anomaly
  - endpoint
vendors:
  - Splunk
  - Red Hat
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Splunk Add-on for Unix and Linux
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/6/html/security_guide/sec-audit_record_types
  - https://splunkbase.splunk.com/app/833
rules:
  - title: Linux Auditd Daemon Abort Detection
    description: Detects abnormal termination of the Linux audit daemon (auditd) by identifying DAEMON_ABORT events in audit logs.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.012
    data_sources:
      - process_creation
      - linux
  - title: Linux Auditd Configuration File Modification
    description: Detects modifications to auditd configuration files, which could indicate an attempt to disable or tamper with auditing.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.012
    data_sources:
      - file_event
      - linux
rules_count: 2
---

This detection identifies abnormal terminations of the Linux audit daemon (auditd) by monitoring for DAEMON_ABORT events within audit logs. Such terminations suggest a critical failure in the auditing subsystem, potentially stemming from resource exhaustion, data corruption, or malicious actions aimed at disrupting the logging process. Unlike a graceful shutdown, a DAEMON_ABORT event implies that audit logging may have been disabled unexpectedly, compromising system observability and security monitoring. Defenders should prioritize investigating these events, correlating them with DAEMON_START, DAEMON_END, and overall system logs to pinpoint the root cause. Recurring aborts or the absence of a subsequent DAEMON_START signal indicate a high-severity issue requiring immediate attention to ensure continued log integrity and security posture.

## Attack Chain

1.  Attacker gains initial access to the system (e.g., through exploiting a vulnerability or using stolen credentials).
2.  Attacker escalates privileges to a level where they can interact with system services.
3.  Attacker attempts to corrupt auditd's configuration or data files, causing it to fail.
4.  The auditd daemon encounters an unrecoverable error and generates a DAEMON_ABORT event in the audit logs.
5.  The system administrator may not immediately notice the auditd failure, leaving a gap in security monitoring.
6.  Attacker performs malicious activities without being properly logged by auditd.
7.  Attacker attempts to remove evidence of the auditd failure from system logs.
8.  The attacker achieves their objective, such as data theft or system compromise, with reduced risk of detection.

## Impact

A successful attack leading to auditd daemon aborts can severely compromise an organization's security monitoring capabilities. With audit logging disabled or unreliable, malicious activities can go undetected, leading to data breaches, system compromise, and other security incidents. The absence of reliable audit logs can also hinder incident response efforts and forensic investigations, making it difficult to determine the scope and impact of an attack. Organizations in regulated industries may also face compliance issues due to the lack of complete audit trails.

## Recommendation

*   Enable Linux auditd logging to capture DAEMON_ABORT events (see `data_source` in search definition).
*   Deploy the provided Sigma rule to your SIEM to detect DAEMON_ABORT events and tune the rule based on your environment.
*   Investigate any detected DAEMON_ABORT events by correlating them with DAEMON_START, DAEMON_END, and system logs to determine the root cause.
*   Monitor the time between DAEMON_ABORT and DAEMON_START events to identify potential issues requiring further investigation.
*   Use Splunk Add-on for Unix and Linux (https://splunkbase.splunk.com/app/833) to ensure proper parsing and categorization of auditd data.
