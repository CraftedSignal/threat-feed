---
title: QEMU Guest Agent Vulnerability Allows Local Privilege Escalation (CVE-2026-12080)
slug: 2026-07-qemu-guest-agent-privesc
description: A local unprivileged user within a QEMU guest can exploit CVE-2026-12080, a vulnerability in the QEMU Guest Agent's 'guest-ssh-add-authorized-keys' command handler, by manipulating symbolic links through a directory-symlink bypass or a Time-of-Check to Time-of-Use (TOCTOU) file-symlink race to gain ownership of arbitrary root-owned files or directories, leading to root access within the guest OS.
date: "2026-07-20T13:21:23Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - vulnerability
  - qemu
  - guest-agent
vendors:
  - QEMU
products:
  - QEMU Guest Agent
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A local unprivileged user can exploit a vulnerability in the guest-ssh-add-authorized-keys command handler... Successful exploitation allows the attacker to gain ownership of arbitrary root-owned files or directories, leading to root access.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: By manipulating symbolic links. This can occur either through a deterministic directory-symlink bypass or a Time-of-Check to Time-of-Use (TOCTOU) file-symlink race.
    confidence_band: high
cves:
  - id: CVE-2026-12080
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-12080
---

A significant local privilege escalation vulnerability, tracked as CVE-2026-12080, has been identified in the QEMU Guest Agent (qga). This flaw allows a local unprivileged user within a QEMU guest operating system to achieve root access. The vulnerability resides within the `guest-ssh-add-authorized-keys` command handler, which can be triggered by an external management layer like libvirt. Attackers can exploit this by manipulating symbolic links, either through a deterministic directory-symlink bypass or by winning a Time-of-Check to Time-of-Use (TOCTOU) file-symlink race. Successful exploitation enables the attacker to gain ownership of arbitrary root-owned files or directories, thereby escalating their privileges to root within the guest system. The exploit requires the guest-ssh-add-authorized-keys command to be invoked, which is typically done by management tools.

## Attack Chain

1. A local unprivileged user first gains access to the QEMU guest operating system.
2. The user identifies the QEMU Guest Agent (qga) process running with root privileges and recognizes the `guest-ssh-add-authorized-keys` command handler as an exploitable component.
3. The attacker waits for or orchestrates an external management layer (such as libvirt) to invoke the `guest-ssh-add-authorized-keys` command on the guest agent.
4. Concurrently with the command execution, the attacker creates and manipulates symbolic links within the guest file system, targeting critical root-owned files or directories.
5. The attacker successfully exploits either a deterministic directory-symlink bypass or a Time-of-Check to Time-of-Use (TOCTOU) file-symlink race within the `guest-ssh-add-authorized-keys` command handler.
6. As a result of the symlink manipulation, the root-privileged QEMU Guest Agent performs file ownership modifications on the attacker-controlled target (arbitrary root-owned files or directories) instead of the intended SSH authorized_keys file.
7. The attacker leverages the newly gained ownership over these critical root-owned files or directories to achieve full root access within the guest operating system.

## Impact

Successful exploitation of CVE-2026-12080 grants a local unprivileged attacker complete root access within the affected QEMU guest operating system. This allows the attacker to fully compromise the guest, including modifying system configurations, installing malicious software, exfiltrating data, or using the compromised guest as a pivot point for further attacks within the virtualized environment. The integrity and confidentiality of data within the guest OS are severely compromised, and the overall security posture of the virtualized infrastructure is weakened.

## Recommendation

* Patch CVE-2026-12080 immediately by updating the QEMU Guest Agent to the fixed version provided by your vendor.
* Monitor system logs for unusual file ownership changes, particularly for root-owned files or directories, which could indicate attempts to exploit CVE-2026-12080.
* Ensure that management layers interacting with the QEMU Guest Agent are configured with the principle of least privilege and their activities are logged for auditing purposes.
