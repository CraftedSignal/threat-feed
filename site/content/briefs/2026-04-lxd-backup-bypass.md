---
title: LXD Backup Import Bypass Allows Privilege Escalation in Restricted Projects
slug: 2026-04-lxd-backup-bypass
description: A vulnerability in LXD allows an attacker with instance-creation rights in a restricted project to bypass project restrictions and escalate privileges by crafting a malicious backup archive.
date: "2026-04-10T19:24:26Z"
severities:
  - critical
tags:
  - lxd
  - privilege-escalation
  - container-escape
  - cve-2026-34178
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1611
    technique_name: Escape to Host
references:
  - https://github.com/advisories/GHSA-q96j-3fmm-7fv4
rules:
  - title: Detect LXD Container Creation with Privileged Mode in Restricted Projects
    description: Detects the creation of LXD containers with 'security.privileged' set to 'true' which is a sign of potential privilege escalation, especially in restricted projects. This requires access to the LXD database.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
      - T1611
    data_sources:
      - file_event
      - linux
  - title: Detect LXD Container Creation with raw.lxc
    description: Detects the creation of LXD containers with 'raw.lxc' config which is a sign of potential privilege escalation, especially in restricted projects. This requires access to the LXD database.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
      - T1611
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A critical vulnerability exists in LXD (versions prior to the fixes mentioned below) that allows an attacker with limited privileges in a restricted project to bypass security restrictions and gain full control of the LXD host. The vulnerability stems from improper validation during instance backup import. Specifically, LXD validates project restrictions against the `backup/index.yaml` file within the backup archive but creates the instance from the `backup/container/backup.yaml` file. By…
