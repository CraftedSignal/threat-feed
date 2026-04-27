---
title: Canonical LXD Backup Import Project Restriction Bypass (CVE-2026-34178)
slug: 2026-04-lxd-backup-bypass
description: An authenticated remote attacker with instance-creation permission in a restricted project can bypass project restrictions in Canonical LXD before 6.8 by crafting a malicious backup archive, leading to full host compromise.
date: "2026-04-09T10:16:21Z"
severities:
  - critical
tags:
  - lxd
  - canonical
  - privilege-escalation
  - vulnerability
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-34178
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34178
rules:
  - title: Detect LXD Backup Import with Suspicious Privileged Configuration
    description: Detects LXD backup import operations that attempt to set privileged configurations, potentially bypassing project restrictions.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect LXD process start with Elevated Privileges
    description: Detects processes started in LXD containers with elevated privileges, which can indicate exploitation of a bypass vulnerability
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Canonical LXD, a container management platform, is vulnerable to a critical security flaw (CVE-2026-34178) affecting versions prior to 6.8. This vulnerability allows an authenticated remote attacker with instance-creation privileges within a restricted project to bypass enforced restrictions. The attack exploits a discrepancy in the backup import process, where project restrictions are validated against `backup/index.yaml`, but the instance is created from `backup/container/backup.yaml`, a…
