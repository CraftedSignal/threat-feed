---
title: LXD Backup Import Bypass Allows Privilege Escalation in Restricted Projects
slug: 2026-04-lxd-backup-bypass
description: A vulnerability in LXD allows an attacker with instance-creation rights in a restricted project to bypass project restrictions and escalate privileges by crafting a malicious backup archive.
date: "2026-04-10T19:24:26Z"
type: coverage
types:
  - coverage
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

A critical vulnerability exists in LXD (versions prior to the fixes mentioned below) that allows an attacker with limited privileges in a restricted project to bypass security restrictions and gain full control of the LXD host. The vulnerability stems from improper validation during instance backup import. Specifically, LXD validates project restrictions against the `backup/index.yaml` file within the backup archive but creates the instance from the `backup/container/backup.yaml` file. By crafting a malicious backup archive where `index.yaml` appears clean while `backup.yaml` contains configurations that violate project restrictions (e.g., `security.privileged=true`, `raw.lxc` host filesystem mounts), an attacker can create a privileged container and escape the restricted environment. This allows them to escalate privileges and potentially compromise the entire LXD host. The attacker needs `can_view_instances`, `can_create_instances`, and `can_operate_instances` permissions. This affects LXD versions up to those patched in April 2026.

## Attack Chain

1.  The attacker creates a local directory structure mimicking an LXD backup archive, including `backup/index.yaml` and `backup/container/backup.yaml`.
2.  The attacker crafts a `backup/index.yaml` file with configurations that satisfy project restrictions (e.g., no privileged mode, no raw.lxc).
3.  The attacker crafts a malicious `backup/container/backup.yaml` file that contains configurations violating project restrictions, such as `security.privileged=true` and `raw.lxc` entries to mount the host's LXD Unix socket.
4.  The attacker packages the crafted directory structure into a tar archive (e.g., `malicious-backup.tar`).
5.  The attacker uses `lxc import target-lxd: malicious-backup.tar --project restricted-project` to import the malicious backup into the target LXD server. LXD validates against `index.yaml` at this stage.
6.  LXD extracts the contents of the tar archive, including the malicious `backup.yaml`, to the storage volume. The actual instance creation uses `backup.yaml` configuration.
7.  The attacker starts the newly created, privileged container using `lxc start target-lxd:escalated-instance --project restricted-project`.
8.  The attacker leverages the bind-mounted LXD Unix socket from within the container to interact with the LXD API as a full administrator, allowing them to create admin certificates, access all projects, and modify any instance, leading to full host compromise.

## Impact

Successful exploitation allows an attacker to completely bypass LXD project restrictions and gain full administrative control over the LXD host. This can lead to the compromise of all containers running on the host, data theft, and further malicious activities. The vulnerability affects multi-tenant environments where LXD is used to isolate different users or projects, allowing a malicious tenant to break out of their restricted environment and compromise the entire system.

## Recommendation

*   Apply the patches provided by Canonical for LXD versions 6, 5.21, and 5.0 to remediate the vulnerability. Specifically, upgrade to LXD 6.7, LXD 5.21.4, or LXD 5.0.6.
*   Monitor LXD server logs for suspicious `lxc import` commands, especially those targeting restricted projects. While difficult to detect solely on command line arguments, anomalous import patterns could be a sign of attempted exploitation.
*   Deploy the provided Sigma rule to detect the creation of containers with `security.privileged` set to true or with `raw.lxc` configurations in restricted projects by analyzing the LXD database (if accessible).
*   As a defense-in-depth measure, consider implementing filesystem integrity monitoring on the LXD storage volumes to detect unauthorized modifications to container configurations.
