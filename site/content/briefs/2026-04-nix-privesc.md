---
title: Nix Package Manager Arbitrary File Overwrite Vulnerability
slug: 2026-04-nix-privesc
description: A flaw in Nix package manager allows arbitrary file overwrites via symlink following during fixed-output derivation registration, potentially leading to root privilege escalation on multi-user Linux systems.
date: "2026-04-09T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - nix
  - privilege-escalation
  - linux
  - vulnerability
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2024-27297
    cvss: 6.3
    epss: 0.0005
  - id: CVE-2026-39860
    cvss: 9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39860
rules:
  - title: Detect Modification of Sensitive Files by Nix Daemon
    description: Detects modifications to sensitive system files (e.g., /etc/passwd, /etc/shadow) by the nix-daemon process, indicating potential privilege escalation.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
  - title: Detect Suspicious Symlink Creation in Nix Build Directory
    description: Detects the creation of symlinks within the Nix build directory, which could be indicative of an attempt to exploit CVE-2026-39860.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A vulnerability exists in the Nix package manager for Linux systems, stemming from an incomplete fix for CVE-2024-27297. The flaw, identified as CVE-2026-39860, allows for arbitrary file overwrites due to improper handling of symlinks during the registration of fixed-output derivation outputs. This occurs when a derivation builder creates a symlink within the build chroot pointing to an arbitrary location in the filesystem. Subsequently, the Nix process, operating in the host mount namespace, follows this symlink and overwrites the destination with the derivation's output. This issue primarily affects sandboxed Linux builds, while macOS builds remain unaffected. The vulnerability poses a significant risk in multi-user Nix installations where any user with build submission privileges (i.e., those allowed by 'allowed-users') can exploit this flaw to gain root privileges by modifying sensitive system files. The vulnerability has been patched in Nix versions 2.34.5, 2.33.4, 2.32.7, 2.31.4, 2.30.4, 2.29.3, and 2.28.6.

## Attack Chain

1.  A malicious user, with privileges to submit builds to the Nix daemon, crafts a Nix derivation designed to exploit the vulnerability.
2.  The malicious derivation includes instructions to create a symlink within the build chroot. This symlink points to a sensitive system file outside of the chroot environment, such as `/etc/shadow` or `/etc/passwd`.
3.  The Nix daemon initiates the build process within a sandboxed environment. The derivation builder creates the specified symlink during the build.
4.  During the fixed-output derivation output registration phase, the Nix process attempts to copy the output from the temporary output location to the Nix store.
5.  The Nix process encounters the malicious symlink. Due to insufficient validation, it follows the symlink to the target file in the root filesystem.
6.  The Nix process overwrites the contents of the target file with the derivation's output, effectively modifying the sensitive system file.
7.  By overwriting a file like `/etc/shadow`, the attacker can manipulate user account information, including password hashes.
8.  The attacker gains root privileges by logging in as a modified or newly created user.

## Impact

Successful exploitation of this vulnerability in multi-user Nix installations allows any user capable of submitting builds to the Nix daemon to achieve root privilege escalation. This could lead to complete system compromise, including data theft, modification, or destruction. The severity is critical because it bypasses standard security measures and directly impacts system integrity. The number of potentially affected systems is broad, encompassing any Linux system utilizing a vulnerable version of Nix in a multi-user configuration, which is a common setup.

## Recommendation

*   Immediately upgrade Nix to version 2.34.5, 2.33.4, 2.32.7, 2.31.4, 2.30.4, 2.29.3, or 2.28.6 to patch CVE-2026-39860.
*   Monitor process creation events for suspicious activity related to `nix-daemon` and file modifications in sensitive directories such as `/etc/passwd` and `/etc/shadow` using the provided Sigma rule.
*   Implement file integrity monitoring (FIM) on sensitive system files to detect unauthorized modifications.
*   Regularly audit and restrict the `allowed-users` configuration of the Nix daemon to minimize the attack surface.
