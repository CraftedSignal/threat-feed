---
title: Local Privilege Escalation in cifs-utils via Credential File Injection
slug: 2026-10-cifs-utils-lpe
description: A local privilege escalation vulnerability in cifs-utils (CVE-2026-104715) allows unprivileged users to gain root access by injecting malicious mount options into a user-controlled credentials file used by mount.cifs.
date: "2026-10-15T23:05:21Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - linux
  - cifs-utils
vendors:
  - Samba
products:
  - cifs-utils (7.0 - 7.6)
affected_os:
  - Ubuntu 24.04
  - RHEL 9.8
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An unprivileged user who controls the credentials file gets arbitrary kernel mount options. That's enough for a root shell.
    confidence_band: high
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Audit local file system for files used by mount.cifs as credential stores and verify restricted ownership/permissions.
      owner: IT Operations
      due: 24h
      evidence: Exploit relies on controlling the credentials file.
  mitigation_plan:
    - priority: immediate
      action: Upgrade cifs-utils to the latest version as provided by the distribution vendor.
      owner: IT Operations
      addresses: CVE-2026-104715
      evidence: Maintainer has developed patches for credential file injection.
---

CVE-2026-104715 is a critical local privilege escalation vulnerability affecting the `mount.cifs` utility within the `cifs-utils` package. The vulnerability stems from improper sanitization of the `username` field within credential files provided via the `credentials=` mount option. Because `mount.cifs` copies the `username` value into the kernel-bound mount option string without filtering for comma separators, an attacker who controls a local credential file can inject arbitrary mount parameters. Since the Linux kernel CIFS parser follows a last-write-wins logic, these injected parameters override earlier, legitimate security settings. By successfully injecting options such as `uid=0`, `forceuid`, and `file_mode=04755`, an attacker can gain a root shell through privileged mount operations performed by administrators, systemd units, or autofs. The vulnerability affects `cifs-utils` versions 7.0 through 7.6 and bypasses SELinux targeted policies.

## Attack Chain

1. Attacker identifies a local `credentials` file or path that is currently or will be used by `mount.cifs` with root privileges.
2. Attacker modifies the credentials file, injecting malicious options into the `username` field (e.g., `username=user,uid=0,forceuid,file_mode=04755`).
3. A privileged process (e.g., administrator, systemd, or autofs) triggers a mount operation using the compromised credential file.
4. `mount.cifs` parses the file and concatenates the malicious `username` string into the kernel mount option buffer.
5. The kernel parses the final mount option string; due to the last-write-wins behavior, the injected `uid=0` and permission-altering options override the default system settings.
6. The CIFS share is mounted with the attacker's desired permissions, effectively granting the attacker full control over file ownership and SUID bits on the mounted filesystem.
7. Attacker executes a binary or modifies files on the now-accessible share to gain persistence or escalate to a root shell.

## Impact

Successful exploitation results in full local privilege escalation, allowing an unprivileged user to gain root access. This affects any system using `cifs-utils` for network filesystem management, including enterprise distributions such as Ubuntu 24.04 and RHEL 9.8. The attack is particularly dangerous because it does not require setuid permissions on `mount.cifs` or the presence of `pam_mount`, and it remains effective even when SELinux is in enforcing mode.

## Recommendation

* Prioritize updating `cifs-utils` to versions containing the fix provided by the maintainer (Paulo Alcantara) to enforce sanitization of credential file values.
* Audit all `fstab` entries, systemd `.mount` units, and administrative scripts that use the `credentials=` mount option to ensure credential files are stored in directories with restricted write access.
* Restrict write access to any files used as CIFS credentials to the specific user account authorized to use that share, preventing unauthorized injection.
* Monitor system logs for unexpected or unauthorized mount operations, particularly those involving modifications to credential configuration files.
