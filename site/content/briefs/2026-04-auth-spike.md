---
title: Spike in Successful Logon Events from a Source IP
slug: 2026-04-auth-spike
description: A machine learning job detected a spike in successful authentication events from a source IP address, which can indicate password spraying, user enumeration, or brute force activity, potentially leading to credential access.
date: "2026-04-02T13:25:14Z"
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

This alert triggers when an Elastic machine learning job identifies a significant spike in successful authentication events originating from a specific source IP address. The underlying cause may range from legitimate administrative activity to malicious attempts at credential compromise, such as password spraying, user enumeration, or brute force attacks. The rule requires a minimum Elastic Stack version of 9.4.0 and relies on data ingested via Elastic Defend, Auditd Manager, or the System…
