---
title: Spike in Successful Logon Events from a Source IP
slug: 2026-04-auth-spike
description: A machine learning job detected a spike in successful authentication events from a source IP address, which can indicate password spraying, user enumeration, or brute force activity, potentially leading to credential access.
date: "2026-04-02T13:25:14Z"
type: coverage
types:
  - coverage
severities:
  - low
tags:
  - credential-access
  - defense-evasion
  - brute-force
  - password-spraying
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
rules:
  - title: Potential Password Spraying Activity Detected via Multiple Failed Logons
    description: Detects a high number of failed logon attempts followed by a successful logon from the same source IP, which could indicate password spraying.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110.003
    data_sources:
      - authentication
      - windows
  - title: Linux Auditd - Multiple Failed SSH Logins from Single IP
    description: Detects multiple failed SSH login attempts from a single source IP address using Auditd logs, indicative of brute force or password spraying attempts.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110
    data_sources:
      - authentication
      - linux
rules_count: 2
---

This alert triggers when an Elastic machine learning job identifies a significant spike in successful authentication events originating from a specific source IP address. The underlying cause may range from legitimate administrative activity to malicious attempts at credential compromise, such as password spraying, user enumeration, or brute force attacks. The rule requires a minimum Elastic Stack version of 9.4.0 and relies on data ingested via Elastic Defend, Auditd Manager, or the System integration. The machine learning job associated with this rule is named "auth_high_count_logon_events_for_a_source_ip_ea". While build servers and CI systems can trigger this alert as false positives, its presence should always prompt investigation to rule out credential compromise attempts.

## Attack Chain

1.  Initial Access: An attacker gains initial access to a network or system (not explicitly described in source).
2.  Credential Harvesting: The attacker attempts to gather valid credentials through password spraying or brute-force attacks (T1110, T1110.003).
3.  Account Discovery: The attacker enumerates user accounts to identify potential targets, often performed in conjunction with password attacks.
4.  Successful Authentication: Using compromised credentials, the attacker successfully authenticates to a system or service (T1078, T1078.002, T1078.003).
5.  Lateral Movement: After successful authentication, the attacker potentially moves laterally within the network using valid accounts (not explicitly described in source).
6.  Privilege Escalation: The attacker may attempt to escalate privileges to gain higher-level access (not explicitly described in source).
7.  Data Exfiltration/Impact: After gaining sufficient access, the attacker may exfiltrate sensitive data or cause damage to the system or network (not explicitly described in source).

## Impact

Successful exploitation can lead to unauthorized access to sensitive data, systems, and services. The number of affected users and the extent of the damage depend on the scope of the compromised credentials and the attacker's objectives. This can impact any sector, as credential compromise is a common attack vector across various industries.

## Recommendation

*   Enable and configure the Elastic Defend, Auditd Manager, or System integrations to provide the necessary data for the machine learning job (see Setup section).
*   Install the associated Machine Learning job "auth_high_count_logon_events_for_a_source_ip_ea" to enable the detection (see Setup section).
*   Tune the anomaly threshold of the machine learning job based on your environment to reduce false positives (anomaly_threshold metadata).
*   Investigate alerts triggered by this rule, focusing on identifying the involved assets, users, and source IP addresses (see Note section).
