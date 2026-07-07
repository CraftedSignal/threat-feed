---
title: Incus Restricted Project Bypass Leading to Arbitrary Command Execution (CVE-2026-48751)
slug: 2026-07-incus-rce-restricted-project-bypass
description: A critical vulnerability, CVE-2026-48751, in Incus versions prior to 7.2.0, allows an attacker to bypass restricted project settings via malicious instance snapshots, enabling arbitrary command execution with root privileges on the Incus server by abusing low-level hooks.
date: "2026-07-03T10:38:26Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - container-security
  - linux
  - privilege-escalation
  - rce
  - incus
vendors:
  - LXC
products:
  - Incus (< 7.2.0)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: arbitrary command execution on the Incus server by abusing lowlevel hooks such as `raw.lxc` and `raw.qemu`
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: In practice, this allows a malicious actor to execute arbitrary commands on the host with root privileges.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-48q5-w887-33wv
rules:
  - title: Detect CVE-2026-48751 Exploitation — Incus Low-Level Hook Configuration
    description: Detects CVE-2026-48751 exploitation - Attempts to configure low-level Incus container hooks (raw.lxc or raw.qemu) via the 'incus config set' command, indicating a potential bypass attempt for restricted projects or malicious configuration.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

A critical vulnerability (CVE-2026-48751) has been identified in Incus, affecting all versions prior to 7.2.0. This flaw allows a malicious actor to achieve arbitrary command execution with root privileges on the Incus server. The vulnerability stems from instance snapshots ignoring the `restricted.containers.lowlevel=block` setting. Attackers can craft a malicious Incus instance locally, integrate a snapshot configured to abuse low-level hooks like `raw.lxc` or `raw.qemu`, and then transfer this instance to a restricted project. When the malicious snapshot is restored within the restricted environment, the embedded commands are executed on the host, bypassing intended security controls. This allows for complete compromise of the Incus host, enabling persistent access, data exfiltration, or further lateral movement within the network.

## Attack Chain

1.  **Initial Setup (Attacker)**: The attacker creates a local Incus instance (e.g., `images:debian/trixie`) in an unrestricted project on their own system.
2.  **Malicious Hook Injection**: The attacker injects a malicious low-level hook into the local Incus instance's configuration, specifically using `raw.lxc` or `raw.qemu`. For example, `incus config set rce-raw-lxc raw.lxc='lxc.hook.pre-start = /bin/sh -c "/bin/id >/lxc-hook-prestart"'`.
3.  **Snapshot Creation**: A snapshot of the now-malicious local instance is created (e.g., `incus snapshot create rce-raw-lxc snap0`). This snapshot captures the injected malicious hook.
4.  **Hook Removal (Optional but Recommended)**: The attacker removes the `raw.lxc` configuration from the local instance to allow for transfer to the restricted project without immediate detection or conflict.
5.  **Instance Transfer**: The malicious instance with its snapshot is moved from the attacker's local, unrestricted environment to a remote Incus server's restricted project (e.g., `incus move rce-raw-lxc rem: --mode push`).
6.  **Snapshot Restoration**: The attacker restores the malicious snapshot within the restricted project on the remote Incus server (e.g., `incus snapshot restore rem:rce-raw-lxc snap0`). Despite `restricted.containers.lowlevel=block` being active on the remote project, the snapshot restoration process bypasses this control.
7.  **Command Execution**: Upon starting the instance from the restored snapshot (e.g., `incus start rem:rce-raw-lxc`), the pre-start hook embedded in the snapshot executes the arbitrary command (e.g., `/bin/id`) on the Incus host with root privileges.

## Impact

Successful exploitation of CVE-2026-48751 leads to a complete bypass of Incus project restrictions, specifically the `restricted.containers.lowlevel=block` setting designed to prevent such abuses. This directly results in arbitrary command execution on the underlying Incus server, granting an attacker root privileges. Such compromise allows for full control over the host system, potentially enabling further network infiltration, data exfiltration, service disruption, or the deployment of additional malicious payloads. While specific victim counts are not available, all Incus instances running vulnerable versions prior to 7.2.0 are at risk, particularly those hosting untrusted containers or users in restricted projects.

## Recommendation

*   Immediately patch Incus instances to version 7.2.0 or later to remediate CVE-2026-48751.
*   Deploy the provided Sigma rule to detect attempts to configure low-level Incus hooks, which indicates potential exploitation of CVE-2026-48751.
*   Enable comprehensive `process_creation` logging for Linux systems to capture `incus` command executions and the execution of arbitrary commands.
