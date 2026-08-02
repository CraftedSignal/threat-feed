---
title: Local Privilege Escalation in PackageKit via TOCTOU Race Condition
slug: 2026-08-packagekit-lpe
description: CVE-2026-41651 is a local privilege escalation vulnerability in PackageKit that allows unprivileged users to execute arbitrary packages as root by bypassing PolKit via a TOCTOU race condition.
date: "2026-08-02T12:42:23Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:packagekit_project:packagekit:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - linux
  - cve-2026-41651
vendors:
  - Packagekit_Project
products:
  - PackageKit (1.0.2 - 1.3.4)
affected_os:
  - Ubuntu 18.04
  - Ubuntu 26.04
  - Debian Trixie
  - Fedora 43
  - RockyLinux 10.1
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Local privilege escalation via TOCTOU race condition in PackageKit's D-Bus transaction handler.
    confidence_band: high
cves:
  - id: CVE-2026-41651
    cvss: 8.8
    epss: 0.0046
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41651
  - https://github.com/PackageKit/PackageKit/security/advisories/GHSA-f55j-vvr9-69xv
  - https://sploitus.com/exploit?id=8F870A9B-727B-5C66-B186-F473AFA58ADC
---

CVE-2026-41651 is a local privilege escalation vulnerability in PackageKit versions 1.0.2 through 1.3.4. The vulnerability arises from a Time-of-check Time-of-use (TOCTOU) race condition within the D-Bus transaction handler, specifically in `src/pk-transaction.c`. An unprivileged local user can exploit three chained bugs: unconditional flag overwrites, a flawed state-machine guard, and late flag reads during transaction dispatch. By utilizing the `PK_TRANSACTION_FLAG_SIMULATE` flag, an attacker can bypass PolKit authorization checks. This allows a local attacker to install arbitrary packages as root, ultimately facilitating the creation of SUID binaries for full system compromise. The vulnerability affects major Linux distributions, including Ubuntu, Debian, Fedora, and RockyLinux, provided the `packagekitd` service is active.

## Attack Chain

1. The attacker initiates a D-Bus transaction with the PackageKit daemon, setting the transaction state to NEW.
2. The attacker sends an `InstallFiles()` request with the `PK_TRANSACTION_FLAG_SIMULATE` flag, causing the daemon to skip PolKit authorization checks.
3. The daemon moves the transaction to a READY state and queues it as a GLib idle event.
4. The attacker sends a second `InstallFiles()` request on the same transaction using their intended malicious payload.
5. The daemon's flawed state-machine guard rejects the second state transition but fails to roll back the malicious flags and file paths overwritten in the previous step.
6. When the GLib idle event fires, `pk_transaction_run()` is invoked, reading the attacker's corrupted flags and path instead of the authorized ones.
7. The backend processes the malicious package as root, executing its post-installation script.
8. The post-installation script creates a SUID binary (e.g., `/tmp/.suid_bash`), which the attacker executes to gain root-level privileges.

## Impact

Successful exploitation results in full local root privilege escalation. The vulnerability affects a wide range of Linux distributions including Ubuntu, Debian, Fedora, and RockyLinux. Any local user with an active session can exploit this to achieve persistence or system-wide compromise, impacting the integrity and availability of the affected host.

## Recommendation

* Upgrade PackageKit to version 1.3.5 or higher immediately.
* If an upgrade is not feasible, mask the PackageKit service using `systemctl mask packagekit` to prevent the vulnerable daemon from running.
* Audit `/tmp` and similar temporary directories for unexpected SUID binaries, specifically looking for files created by `dpkg` or unauthorized installation processes.
* Monitor for the presence of unusual `.deb` packages being processed by `packagekitd` in environments where package management activity is typically restricted.
