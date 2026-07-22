---
title: Ubuntu Desktop Vulnerability Allows Local Root Access via snap-confine
slug: 2026-07-ubuntu-snap-confine-lpe
description: A high-severity vulnerability, CVE-2026-8933, in Ubuntu's snap-confine component of the snapd service allows an unprivileged local user to gain root access on affected Ubuntu Desktop systems by exploiting race conditions during temporary file creation, enabling full administrative control.
date: "2026-07-22T11:20:49Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - vulnerability
  - linux
  - ubuntu
  - local-access
vendors:
  - Canonical
products:
  - snapd
affected_os:
  - Ubuntu 22.04 LTS
  - Ubuntu 24.04 LTS
  - Ubuntu 25.10
  - Ubuntu 26.04 LTS
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A vulnerability in snap-confine lets an unprivileged user gain root access on affected Ubuntu Desktop systems.
    confidence_band: high
cves:
  - id: CVE-2026-8933
    cvss: 7.8
references:
  - https://hackread.com/ubuntu-desktop-vulnerability-local-access-root-control/
---

Qualys researchers have disclosed a high-severity local privilege escalation vulnerability, CVE-2026-8933, affecting Ubuntu Desktop systems. This flaw resides in `snap-confine`, a crucial part of the `snapd` service responsible for preparing the sandboxed environment where Snap applications run. The vulnerability allows an unprivileged local user to obtain root access by exploiting a race condition during the creation and ownership transfer of temporary files and directories under `/tmp`. This issue arose after a security hardening change replaced `snap-confine`'s setuid-root design with a Linux capabilities model, creating a brief window where a user can manipulate these temporary files. An attacker must first have local access to an affected system, either through a compromised account, stolen credentials, or another vulnerability. Successful exploitation grants complete administrative control, enabling arbitrary code execution as root. Affected Ubuntu Desktop systems include 22.04 LTS, 24.04 LTS, and 26.04 LTS, requiring `snapd` package updates to versions 2.76+ubuntu22.04.1, 2.76+ubuntu24.04.1, and 2.76+ubuntu26.04.3 respectively. Ubuntu 25.10, which reached end-of-life in July 2026, was also affected.

## Attack Chain

1. An attacker gains initial unprivileged local access to an affected Ubuntu Desktop system via various means, such as a compromised user account or a separate vulnerability.
2. The unprivileged attacker executes `snap-confine`, which is part of the `snapd` service and responsible for setting up the environment for Snap packages.
3. `snap-confine` creates temporary files and directories in `/tmp` that are initially owned by the invoking local user, prior to changing ownership to root.
4. During this brief race window, the attacker mounts a malicious FUSE filesystem over one of the temporary directories created by `snap-confine`.
5. The attacker then uses a symbolic link to redirect `snap-confine`'s subsequent file operations to a chosen system location, such as `/run/udev/rules.d/`.
6. Before `snap-confine` transfers ownership of the manipulated file to root, the attacker changes the permissions of the target file via the FUSE filesystem.
7. The attacker writes a malicious rules file to `/run/udev/rules.d/`, which `systemd-udevd` will later process.
8. `systemd-udevd` processes the malicious rule, triggering the execution of attacker-controlled commands with root privileges, leading to full system compromise.

## Impact

A successful exploitation of CVE-2026-8933 leads to an unprivileged local user gaining full administrative control over the affected Ubuntu Desktop system. This allows the attacker to alter arbitrary system files, create additional user accounts with elevated privileges, modify security settings, and install any desired software, including malware or backdoors. While the vulnerability requires prior local access, it provides the attacker with the highest level of control, enabling them to completely compromise the integrity and confidentiality of the system. Organizations with affected Ubuntu Desktop installations running vulnerable `snapd` versions are at critical risk of complete system takeover if an attacker gains initial foothold.

## Recommendation

* Immediately identify all Ubuntu Desktop systems running affected versions of `snapd` within your environment.
* Apply the latest `snapd` updates to patch CVE-2026-8933 on all affected Ubuntu systems, specifically updating to `snapd` versions 2.76+ubuntu22.04.1 for Ubuntu 22.04, 2.76+ubuntu24.04.1 for Ubuntu 24.04, and 2.76+ubuntu26.04.3 for Ubuntu 26.04.
* Ensure that Ubuntu 25.10 systems are migrated to a currently supported release as it has reached end-of-life and will not receive further patches for CVE-2026-8933.
* Regularly verify `snapd` package versions to ensure systems are running patched versions.
