---
title: Critical Incus Vulnerability (CVE-2026-48752) Allows Host Arbitrary File Read/Write Leading to RCE
slug: 2026-07-incus-afrw
description: A critical vulnerability, CVE-2026-48752, in Incus versions prior to 7.2.0 allows an unauthenticated attacker to achieve arbitrary file read and write on the host system via specially crafted container images or instance backups containing unsanitized symlinks, potentially leading to arbitrary command execution as root.
date: "2026-07-03T10:37:30Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - rce
  - symlink
  - linux
  - incus
  - container
vendors:
  - Incus
products:
  - incusd (< 7.2.0)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A specially crafted image or instance backup can be used to read or create/write arbitrary files on the host; possibly leading to arbitrary command execution.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: A specially crafted image or instance backup can be used to read or create/write arbitrary files on the host.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: A specially crafted image or instance backup can be used to read or create/write arbitrary files on the host.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: create a cronjob to run `id` as root.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: printf "* * * * * root sh -c 'id>/pwned'\n" | incus config template create
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: possibly leading to arbitrary command execution.
    confidence_band: med
references:
  - https://github.com/advisories/GHSA-vxp5-584q-c479
rules:
  - title: Detects CVE-2026-48752 Exploitation - Incus Writing to Sensitive System Directories
    description: Detects CVE-2026-48752 exploitation where the 'incusd' process writes or creates files in sensitive system directories (e.g., /etc/cron.d) due to a symlink following vulnerability. This indicates arbitrary file write on the host.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
      - privilege_escalation
    techniques:
      - T1059.004
      - T1068
      - T1543.003
    data_sources:
      - file_event
      - linux
rules_count: 1
---

A critical vulnerability tracked as CVE-2026-48752 has been identified in Incus, a Linux container manager, affecting versions prior to 7.2.0. This flaw allows a malicious actor to perform arbitrary file read and write operations on the underlying host system. The exploitation vector involves crafting a malicious container image or instance backup that includes a top-level `templates` symlink. When Incus unpacks such an artifact, it fails to properly sanitize this symlink, enabling the attacker to redirect operations intended for the `templates` directory to any arbitrary path on the host, such as `/etc/cron.d`. This capability can be leveraged to inject malicious cron jobs or modify other sensitive system files, ultimately leading to arbitrary command execution with root privileges on the host. This vulnerability poses a significant risk to the integrity and security of systems running vulnerable Incus instances.

## Attack Chain

1.  The attacker crafts a malicious Incus container image or instance backup (`.tar` archive).
2.  Within this archive, a top-level symlink named `templates` is created, pointing to a sensitive host directory (e.g., `/etc/cron.d`).
3.  The attacker distributes this malicious image or backup, which is then imported or restored on a vulnerable Incus host using `incus image import` or `incus import`.
4.  During the unpacking process, Incus's `archive.Unpack` (for images) or `rsync.LocalCopy` (for backups) follows the `templates` symlink due to insufficient sanitization.
5.  The attacker then uses `incus config template create` or `incus config template edit` commands, targeting the newly imported malicious instance/image.
6.  Due to the symlink, these `incus` commands inadvertently write arbitrary content to the sensitive host directory (e.g., creating a new cron job file in `/etc/cron.d`).
7.  The malicious cron job is executed by the host's cron daemon, achieving arbitrary command execution, often as root, on the host system.
8.  The attacker gains full control over the Incus host, enabling further malicious activities like data exfiltration or deploying additional malware.

## Impact

The successful exploitation of CVE-2026-48752 leads to arbitrary file read and write capabilities on the Incus host system. This direct access to the host filesystem allows attackers to modify critical system files, inject malicious configurations (such as cron jobs), and ultimately achieve arbitrary command execution, often with root privileges. The consequences include complete system compromise, unauthorized data access, persistence mechanisms, and potential disruption of services. While no specific victim count or sectors are mentioned, any organization utilizing vulnerable Incus installations could be at risk of severe security breaches and operational disruption.

## Recommendation

*   Patch Incus immediately to version 7.2.0 or newer to address CVE-2026-48752 as advised by the vendor.
*   Deploy the Sigma rule below to detect suspicious `incusd` write operations to sensitive system directories.
*   Enable comprehensive `file_event` logging for Linux systems to capture modifications within critical directories like `/etc/cron.d/`, `/etc/`, `/bin/`, `/sbin/` by the `incusd` process.
