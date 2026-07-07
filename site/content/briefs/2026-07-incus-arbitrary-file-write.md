---
title: Incus Arbitrary File Write Vulnerability via `exec-output` Symlink (CVE-2026-48750)
slug: 2026-07-incus-arbitrary-file-write
description: The `exec` endpoint in Incus is vulnerable to an arbitrary file write on the host system via a crafted image containing an `exec-output` symlink, allowing an attacker to achieve arbitrary command execution, persistence, and privilege escalation on the host.
date: "2026-07-03T10:39:47Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - incus
  - container-escape
  - arbitrary-file-write
  - rce
  - linux
  - privilege-escalation
  - persistence
vendors:
  - lxc
products:
  - Incus (< 7.2.0)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: Below, we place the `exec_UUID.stdout` file in `/etc/cron.d` on the host for arbitrary command execution.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Constrained file creation in an arbitrary directory on the host via via an unsanitized symlink; possibly leading to command execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: possibly leading to command execution.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-73hr-m85f-64v9
rules:
  - title: Detects CVE-2026-48750 Exploitation - Incus Daemon Writing to Cron.d
    description: Detects CVE-2026-48750 exploitation by monitoring for the Incus daemon (`incusd`) creating or modifying files matching the 'exec_*.stdout' pattern in the `/etc/cron.d` directory, indicating a successful arbitrary file write for persistence or privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1053.003
      - T1068
    data_sources:
      - file_event
      - linux
rules_count: 1
---

A critical arbitrary file write vulnerability, tracked as CVE-2026-48750, has been identified in Incus (versions prior to 7.2.0). Attackers can exploit this by crafting a malicious Incus image containing a symbolic link named `exec-output` pointing to an arbitrary, sensitive directory on the host system (e.g., `/etc/cron.d`). When an instance is launched from this image and a command is executed via the `/instances/$name/exec` endpoint with the `record-output` parameter set to `true`, the Incus daemon follows the symlink. This redirection causes the output of the executed command to be written to the attacker-controlled host directory. This allows for arbitrary file creation with arbitrary content, which can be abused for various malicious purposes, including establishing persistence through cron jobs or achieving privilege escalation and arbitrary command execution on the host system. Defenders should prioritize patching and monitoring for unusual image imports and host file modifications.

## Attack Chain

1.  An attacker crafts a malicious Incus image that includes a symbolic link named `exec-output` pointing to a sensitive host directory, such as `/etc/cron.d`.
2.  The attacker imports this specially crafted image into an Incus environment, which extracts the `exec-output` symlink to disk during unpacking.
3.  The attacker launches an Incus container instance from the malicious image.
4.  The attacker makes a POST request to the `/instances/$name/exec` API endpoint on the Incus daemon, specifying a command to execute inside the container and setting the `record-output` parameter to `true`.
5.  The Incus daemon (`incusd`) executes the command and, due to the `os.OpenFile` function following the `exec-output` symlink, writes the command's standard output (`exec_UUID.stdout`) to the arbitrary host directory specified by the attacker (e.g., `/etc/cron.d`).
6.  By writing a specially crafted cron job entry to `/etc/cron.d` as the command's output, the attacker achieves arbitrary command execution on the host system.
7.  This successful exploitation results in persistence and privilege escalation on the Incus host.

## Impact

Successful exploitation of CVE-2026-48750 grants an attacker the ability to perform arbitrary file writes to any location on the Incus host system. This direct access allows for several severe consequences, including the creation of new user accounts, modification of system configurations, or, as demonstrated in the PoC, the installation of persistent cron jobs. This leads to arbitrary command execution on the host, effectively resulting in a container escape scenario combined with privilege escalation and persistence. The vulnerability affects critical infrastructure running Incus containers, potentially allowing attackers to gain full control over the underlying host and any other containers running on it, impacting data integrity, confidentiality, and system availability.

## Recommendation

*   Immediately patch Incus instances to version 7.2.0 or newer to remediate CVE-2026-48750.
*   Deploy the Sigma rule provided in this brief to your SIEM solution to detect suspicious file creations by the `incusd` process.
*   Implement host-based logging for file creation events, specifically monitoring modifications within critical system directories like `/etc/cron.d` for files originating from the `incusd` process.
*   Restrict access to the Incus daemon's Unix socket (`/var/lib/incus/unix.socket`) to only trusted users and processes, as the exploitation relies on interacting with this API.
