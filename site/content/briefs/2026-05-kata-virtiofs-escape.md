---
title: Kata Containers Guest-to-Host Root Escape via Virtiofs FUSE_SYMLINK
slug: 2026-05-kata-virtiofs-escape
description: A vulnerability in Kata Containers allows a guest root user to escalate privileges to host root by exploiting the virtiofs shared file system to create arbitrary symlinks on the host.
date: "2026-05-27T22:51:24Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - kata-containers
  - virtiofs
  - fuse
  - privilege-escalation
  - container-escape
vendors:
  - kata-containers
products:
  - kata-containers/kata-containers (< 0.0.0-20260519062212-ffa59ce3aa78)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-2gv2-cffp-j227
rules:
  - title: Detect Cron Job File Creation
    description: Detects the creation of new cron job files in /etc/cron.d, which could indicate malicious activity if the container isolation is bypassed.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1543.002
    data_sources:
      - file_event
      - linux
  - title: Detect Virtiofsd Process Running Without Seccomp
    description: Detects if virtiofsd is running without seccomp, which is a potential indicator of a vulnerable configuration as described in CVE-2026-47243.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A guest-to-host root escape vulnerability exists in Kata Containers when using the runtime-rs standalone virtio-fs path. This configuration, which runs `virtiofsd` on the host as root without sandboxing or seccomp, allows a malicious actor with root privileges inside the Kata guest VM to send raw FUSE requests directly to the host `virtiofsd`. Specifically, the `FUSE_SYMLINK` request can be leveraged to create arbitrary symlinks outside the intended virtio-fs shared directory. By creating symlinks in sensitive host paths like `/etc/cron.d`, an attacker can inject and execute arbitrary code as host root. This attack bypasses the guest kernel's normal filesystem validation and directly interacts with the host's file system management. The vulnerability affects Kata Containers versions prior to commit `2ffd1538a296cff93a357bfba0dfca747480a1f8`, and is reproducible using QEMU and Cloud Hypervisor.

## Attack Chain

1. Attacker gains root-equivalent access inside the Kata guest VM.
2. Attacker identifies the virtio-fs PCI device within the guest using `/sys/devices/pci*`.
3. Attacker takes control of a virtio-fs queue in userspace, bypassing the guest kernel's virtio-fs client.
4. Attacker sends a `FUSE_INIT` request to initialize the FUSE connection.
5. Attacker discovers the runtime-rs sandbox ID and constructs the path to a guest-controlled payload, such as `/tmp/kata-go-escape-payload`, using the `passthrough` mount.
6. Attacker crafts a raw `FUSE_SYMLINK` request. The request specifies a new symlink name as an absolute path on the host, e.g., `/etc/cron.d/kata-go-escape-cron-<pid>`, and sets the symlink target to point to the guest-controlled payload through a `/proc/<pid>/root/...` path.
7. The host `virtiofsd` receives the `FUSE_SYMLINK` request and, due to the lack of proper validation, creates the symlink on the host filesystem in the specified location.
8. Host cron reads the `/etc/cron.d` directory, follows the newly created symlink, and executes the guest-controlled payload as host root.

## Impact

Successful exploitation leads to complete compromise of the host system, as the attacker gains the ability to execute arbitrary commands as root. This allows the attacker to bypass the Kata Containers isolation and potentially access sensitive data, disrupt services, or further compromise the host infrastructure. The provided PoC demonstrated this vulnerability, confirming guest-root to host-root command execution by creating a proof file in the host's `/run` directory. This bypasses the container's isolation and impacts the entire host system.

## Recommendation

*   Upgrade to a patched version of Kata Containers that addresses CVE-2026-47243 to prevent exploitation.
*   Monitor process creation events on the host for the execution of unexpected binaries from `/etc/cron.d` using the provided Sigma rule `Detect Cron Job File Creation`.
*   Implement host-based intrusion detection systems (HIDS) to monitor for suspicious file system activity, particularly the creation of symlinks in sensitive directories such as `/etc/cron.d`.
*   Review and harden the configuration of `virtiofsd` to ensure proper validation of file paths and prevent the creation of symlinks outside the intended shared directory.
*   Enable and configure seccomp profiles to restrict the capabilities of the `virtiofsd` process, limiting its ability to perform actions that could lead to privilege escalation.
