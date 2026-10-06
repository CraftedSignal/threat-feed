---
title: Path Traversal in lrzsz lrz Utility
slug: 2026-10-lrzsz-path-traversal
description: The lrz receive utility in lrzsz versions before 0.13.0 fails to properly sanitize absolute pathnames in restricted mode, allowing malicious ZMODEM senders to overwrite arbitrary files writable by the receiving user.
date: "2026-10-06T14:56:09Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:lrzsz:lrzsz:*:*:*:*:*:*:*:*
vendors:
  - lrzsz
products:
  - lrzsz (< 0.13.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The utility fails to validate absolute pathnames, allowing a malicious ZMODEM sender to write files outside the current directory.
    confidence_band: high
cves:
  - id: CVE-2026-105840
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105840
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade lrzsz to version 0.13.0 or later.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-105840 fix requirement
  mitigation_plan:
    - priority: immediate
      action: Upgrade lrzsz to 0.13.0.
      owner: IT Operations
      addresses: CVE-2026-105840
      evidence: NVD vulnerability details
---

The lrz utility, part of the lrzsz package used for X/Y/ZMODEM file transfers, contains a path traversal vulnerability (CVE-2026-105840) in its restricted mode. This vulnerability stems from the checkpath() function in src/lrz.c, which fails to adequately filter absolute pathnames. While the software attempts to reject '../' traversal sequences, it does not account for absolute paths when not compiled with the --enable-pubdir option. An attacker acting as a ZMODEM sender can leverage this flaw to write or overwrite files outside the intended destination directory, provided the user running lrz has the necessary file system permissions. This vulnerability is particularly critical in environments where lrz is used to facilitate automated file uploads, as it allows for arbitrary file write scenarios that can lead to remote code execution or system configuration compromise if sensitive files like .ssh/authorized_keys or shell profiles are targeted.

## Impact

Successful exploitation allows an unauthenticated remote attacker or a malicious ZMODEM sender to overwrite system files or user-specific configuration files. This can result in privilege escalation, persistence establishment, or remote code execution, depending on the privileges of the account executing the lrz process. The vulnerability affects all systems utilizing lrzsz versions prior to 0.13.0 for ZMODEM file transfers.

## Recommendation

- Upgrade lrzsz to version 0.13.0 or later immediately to patch CVE-2026-105840.
- Audit any automated scripts or services that invoke the lrz binary to ensure they are not exposing the application to untrusted ZMODEM senders.
- Run the lrz process with the least privilege possible, utilizing restricted user accounts that lack write access to sensitive system directories or user configuration files.
