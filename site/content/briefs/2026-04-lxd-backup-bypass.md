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

Canonical LXD, a container management platform, is vulnerable to a critical security flaw (CVE-2026-34178) affecting versions prior to 6.8. This vulnerability allows an authenticated remote attacker with instance-creation privileges within a restricted project to bypass enforced restrictions. The attack exploits a discrepancy in the backup import process, where project restrictions are validated against `backup/index.yaml`, but the instance is created from `backup/container/backup.yaml`, a separate file that is not subject to the same validation. Successful exploitation allows attackers to inject malicious configurations, such as `security.privileged=true` or `raw.lxc` directives, effectively escalating privileges and gaining full control over the host system. This poses a significant threat to multi-tenant LXD environments where projects are intended to be isolated.

## Attack Chain

1. Attacker authenticates to LXD with instance-creation permissions within a restricted project.
2. Attacker crafts a malicious backup archive. This archive contains a `backup/index.yaml` file that conforms to the project's restrictions to pass initial validation.
3. The malicious archive also contains a `backup/container/backup.yaml` file with configurations that violate project restrictions, such as `security.privileged=true` or `raw.lxc` directives.
4. The attacker initiates the backup import process using the `lxc import` command, specifying the crafted archive.
5. LXD validates the `backup/index.yaml` file against project restrictions, which passes due to the crafted nature of the file.
6. LXD creates a new instance based on the configurations specified in the `backup/container/backup.yaml` file.
7. Due to the vulnerability, the configurations in `backup/container/backup.yaml` are not checked against project restrictions, allowing the malicious configurations to be applied to the new instance.
8. The attacker gains escalated privileges within the newly created instance, leading to full host compromise.

## Impact

Successful exploitation of CVE-2026-34178 can lead to a complete compromise of the LXD host system. Attackers can bypass project restrictions designed to isolate tenants, allowing them to execute arbitrary code, access sensitive data, and potentially disrupt services for all tenants on the affected host. This vulnerability poses a significant risk to organizations utilizing LXD for container management, particularly in multi-tenant environments where security and isolation are paramount. The CVSS v3.1 base score of 9.1 reflects the criticality of this vulnerability.

## Recommendation

*   Upgrade LXD to version 6.8 or later to patch CVE-2026-34178.
*   Implement strict access control policies to limit instance-creation permissions to only trusted users.
*   Monitor LXD audit logs for suspicious backup import activities that may indicate exploitation attempts. Use the rule `title: "Detect LXD Backup Import with Suspicious Privileged Configuration"` to detect attempts to set privileged configurations via backup import.
