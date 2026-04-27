---
title: Nix Package Manager Arbitrary File Overwrite Vulnerability
slug: 2026-04-nix-privesc
description: A flaw in Nix package manager allows arbitrary file overwrites via symlink following during fixed-output derivation registration, potentially leading to root privilege escalation on multi-user Linux systems.
date: "2026-04-09T12:00:00Z"
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

A vulnerability exists in the Nix package manager for Linux systems, stemming from an incomplete fix for CVE-2024-27297. The flaw, identified as CVE-2026-39860, allows for arbitrary file overwrites due to improper handling of symlinks during the registration of fixed-output derivation outputs. This occurs when a derivation builder creates a symlink within the build chroot pointing to an arbitrary location in the filesystem. Subsequently, the Nix process, operating in the host mount namespace…
