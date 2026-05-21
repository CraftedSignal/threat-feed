---
title: 'Boxlite: Permission Bypass Allows Modification of Read-Only Files via virtiofs'
slug: 2026-05-boxlite-ro-bypass
description: Boxlite, a sandbox service, allows malicious code within a container to bypass read-only restrictions on mounted host directories using virtiofs, due to missing hypervisor-level enforcement and unrestricted kernel capabilities, leading to potential code execution on the host and supply chain risks.
date: "2026-05-21T21:54:26Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - persistence
  - sandbox-escape
vendors:
  - Boxlite
products:
  - Boxlite
affected_os:
  - Alpine Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1611
    technique_name: Escape to Host
references:
  - https://github.com/advisories/GHSA-g6ww-w5j2-r7x3
rules:
  - title: Detect Boxlite Read-Only Bypass via Mount Remount
    description: Detects attempts to bypass read-only restrictions in Boxlite by remounting a filesystem with read-write permissions inside a container.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1611
    data_sources:
      - process_creation
      - linux
  - title: 'Detect Boxlite: Capabilities Granted to Container'
    description: Detects if Boxlite is configured to grant all capabilities to containers, which weakens security.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Boxlite is a sandbox service designed to allow users to execute untrusted code in lightweight virtual machines (Boxes). A key security feature is the ability to mount host directories in read-only mode into the VM using the virtiofs protocol, preventing modifications to host data. However, a vulnerability exists that allows malicious code within the container to bypass these read-only restrictions. This is because Boxlite's implementation relies on adding the MS_RDONLY flag *after* mounting, and does not restrict kernel capabilities.  Malicious code can remount the directory in read-write mode. In typical usage scenarios, such as AI Agent sandboxes where user code, virtual environments, and configuration files are mounted read-only, this vulnerability allows attackers to plant malicious code and gain code execution on the host, leading to supply chain risks. The vulnerability exists because the underlying libkrun library does not support read-only mounts, and Boxlite's guest agent (Zone 0) is not trusted to enforce the restriction.

## Attack Chain

1. A user mounts a host directory into a Boxlite VM with the `read_only` flag set to `true` in the `VolumeSpec`.
2. The Boxlite runtime logs the `read_only` setting but does not pass it to the `krun_add_virtiofs` function, which lacks a read-only parameter.
3. The hypervisor exposes the virtiofs share to the guest with full read-write access at the device level via `libkrun`.
4. The `read_only` flag is sent to the guest agent as a mount instruction via gRPC.
5. The guest agent, running untrusted code, receives the mount instruction with the `read_only` flag.
6. The malicious code uses the `mount` command with the `remount,rw` options to change the mount flags of the virtiofs share from read-only to read-write.
7. The attacker writes to the now writable directory, modifying or creating files on the host system.
8. The attacker gains code execution capability on the host.

## Impact

Successful exploitation allows malicious code running inside a Boxlite sandbox to bypass intended security restrictions and perform arbitrary write operations on directories that were supposed to be read-only.  This can lead to code execution on the host, potentially compromising user data, virtual environments, and configuration files. This is especially dangerous in AI Agent scenarios, potentially leading to supply chain risks by planting malicious code in trusted environments. While the exact number of victims is unknown, the impact on affected Boxlite deployments could be significant, especially those relying on the read-only mount feature for security.

## Recommendation

*   Upgrade to a patched version of Boxlite that addresses the read-only bypass vulnerability (reference: GHSA-g6ww-w5j2-r7x3).
*   Implement a capability drop profile to remove the `CAP_SYS_ADMIN` capability from the container, preventing the remount attack (reference: Attack Chain step 6).
*   Deploy the Sigma rule "Detect Boxlite Read-Only Bypass via Mount Remount" to detect attempts to remount file systems within Boxlite containers (reference: rules).
*   Review all volume specifications to ensure that sensitive host directories are not being mounted into Boxlite VMs without adequate write protection (reference: Attack Chain step 1).
