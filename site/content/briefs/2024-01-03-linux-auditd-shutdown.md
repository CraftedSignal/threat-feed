---
title: Unexpected Linux Auditd Daemon Shutdown
slug: 2024-01-03-linux-auditd-shutdown
description: This analytic detects unexpected shutdowns of the Linux auditd daemon, potentially indicating attempts to disable security monitoring and evade detection by attackers.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - auditd
  - linux
  - defense-evasion
  - endpoint
vendors:
  - Splunk
  - Red Hat
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Red Hat Enterprise Linux
affected_os:
  - linux
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/6/html/security_guide/sec-audit_record_types
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/linux_auditd_auditd_daemon_shutdown.yml
rules:
  - title: Linux Auditd Daemon Shutdown Detected
    description: Detects the termination of the Linux auditd daemon by monitoring for DAEMON_END events.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.012
    data_sources:
      - process_creation
      - linux
  - title: Auditd DAEMON_END Event
    description: Detects auditd daemon shutdown events via the DAEMON_END audit message.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.012
    data_sources:
      - file_event
      - linux
  - title: Detect Auditd Termination via Service Command
    description: Detects auditd termination via the service command.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.012
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

The Linux Audit daemon (auditd) is a critical component for security monitoring on Linux systems. It is responsible for recording system events, including process executions, file accesses, and user logins. Attackers who gain unauthorized access to a system may attempt to disable auditd to prevent their malicious activities from being logged and detected. This brief focuses on detecting the unexpected termination of the auditd daemon, signified by `DAEMON_END` log entries. Monitoring for this event is crucial, as it can indicate a compromised system where security event logging has been disabled, allowing attackers to operate undetected. This detection is based on analysis of auditd logs, specifically looking for `type=DAEMON_END`.

## Attack Chain

1. An attacker gains initial access to the Linux system, potentially through exploiting a vulnerability or using compromised credentials.
2. The attacker escalates privileges to root or an account with sufficient permissions to manage system services.
3. The attacker attempts to stop the auditd service using commands like `systemctl stop auditd` or `service auditd stop`.
4. The operating system logs a `DAEMON_END` event in the audit logs, indicating that the auditd daemon has been terminated.
5. The attacker performs malicious activities, such as installing malware, modifying system configurations, or exfiltrating data.
6. These malicious activities are not logged by auditd, allowing the attacker to operate undetected.
7. The attacker maintains persistence on the system to continue their activities.

## Impact

A successful attack that disables the Linux Audit daemon can severely compromise the security posture of a system. Without audit logging, security teams lose visibility into system activity, making it impossible to detect malicious actions. This can lead to data breaches, system corruption, and prolonged periods of undetected activity. The impact includes potential financial loss, reputational damage, and legal liabilities. Organizations relying on audit logs for compliance purposes will also be affected.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect unexpected `DAEMON_END` events in audit logs.
*   Investigate any detected `DAEMON_END` events to determine the root cause and whether they were authorized (reference the Sigma rule output).
*   Correlate `DAEMON_END` events with other security logs and alerts to identify potentially malicious activity occurring after the auditd shutdown.
*   Ensure proper access controls and monitoring are in place to prevent unauthorized users from stopping the auditd service.
*   Regularly review and update auditd configuration to ensure comprehensive logging of security-relevant events.
*   Install the Splunk Add-on for Unix and Linux to properly ingest and parse auditd data (see How To Implement).
*   Update the filter macros to remove false positives based on your environment (see Known False Positives).
