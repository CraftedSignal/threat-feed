---
title: Rsync TOCTOU Vulnerability Allows File Write Redirection
slug: 2026-05-rsync-toctou
description: Rsync versions before 3.4.3 are vulnerable to a TOCTOU race condition allowing attackers with write access to a module path to redirect file writes outside intended directories by replacing parent directory components with symbolic links, potentially leading to privilege escalation when the daemon runs with elevated privileges and chroot is disabled.
date: "2026-05-20T13:17:51Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - toctou
  - rsync
vendors:
  - rsync
products:
  - rsync (< 3.4.3)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-29518
    cvss: 7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-29518
  - CVE-2026-29518
rules:
  - title: Detect Rsync TOCTOU Attempt via Symlink Creation
    description: Detects CVE-2026-29518 exploitation attempt — Creation of symbolic links in Rsync module paths indicating a TOCTOU vulnerability exploitation attempt.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
  - title: Detect Rsync TOCTOU Attempt via File Modification
    description: Detects CVE-2026-29518 exploitation attempt — Unexpected file modification within Rsync module paths that may indicate a TOCTOU race condition exploit.
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

Rsync before version 3.4.3 is susceptible to a time-of-check to time-of-use (TOCTOU) race condition in how the daemon handles files. This vulnerability allows an attacker with write access to a Rsync module path to manipulate file writes. By replacing parent directory components with symbolic links, an attacker can redirect file writes to locations outside of the intended directories. The vulnerability is triggered when the chroot setting is false. This can lead to arbitrary file creation or overwriting, and potentially escalate privileges if the Rsync daemon runs with elevated permissions. This vulnerability was published in May 2026 and is identified as CVE-2026-29518.

## Attack Chain

1.  Attacker gains write access to a Rsync module path, either through compromised credentials or misconfiguration.
2.  Attacker identifies a target file or location outside of the intended module path.
3.  Attacker crafts a malicious directory structure within the Rsync module path, replacing parent directories with symbolic links pointing to attacker-controlled locations.
4.  Attacker initiates a file transfer operation using Rsync, targeting a file within the crafted malicious directory structure.
5.  Rsync daemon performs initial checks on the directory structure.
6.  Between the check and the actual file write, the attacker modifies the symbolic links to redirect the write operation to the target file or location outside of the Rsync module path.
7.  Rsync daemon writes the file to the attacker-specified location, bypassing intended access controls.
8.  If the attacker overwrites sensitive system files, this can lead to privilege escalation.

## Impact

Successful exploitation of this vulnerability allows attackers to create or overwrite arbitrary files on the system, potentially leading to privilege escalation if the Rsync daemon is running with elevated privileges. If the attacker overwrites critical system binaries or configuration files, they can gain complete control of the system. The impact is limited to systems where the chroot setting is false.

## Recommendation

*   Upgrade Rsync to version 3.4.3 or later to patch CVE-2026-29518.
*   Apply the "Detect Rsync TOCTOU Attempt via Symlink Creation" and "Detect Rsync TOCTOU Attempt via File Modification" Sigma rules to identify potential exploitation attempts.
*   Ensure the chroot setting is enabled in Rsync configurations to mitigate the vulnerability.
