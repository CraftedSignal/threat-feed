---
title: Local Privilege Escalation via Symlink in MRTG Daemon
slug: 2026-08-mrtg-symlink-priv-esc
description: A local symlink following vulnerability in the MRTG daemon allows low-privileged users to achieve local privilege escalation by manipulating PID file ownership.
date: "2026-08-11T09:51:08Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - symlink
  - linux
vendors:
  - Oetiker
products:
  - MRTG
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A local, low-privileged attacker can exploit a symbolic link (symlink) following vulnerability... leading to local privilege escalation.
    confidence_band: high
cves:
  - id: CVE-2026-72694
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72694
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all systems running MRTG as root.
      owner: IT Operations
      due: 48h
      evidence: Source states vulnerability occurs when daemon is started as root.
  mitigation_plan:
    - priority: short_term
      action: Enable fs.protected_symlinks=1 in sysctl settings.
      owner: IT Operations
      addresses: CVE-2026-72694
      evidence: Standard mitigation for symlink-following vulnerabilities.
---

MRTG (Multi Router Traffic Grapher) contains a vulnerability (CVE-2026-72694) in its privilege-dropping mechanism when the daemon is started as root. A low-privileged local user can exploit this by manipulating the path used for the Process ID (PID) file. Because the application fails to verify the target of the PID file path before performing file operations, it can be tricked into following a symbolic link (symlink) to an arbitrary file. When the daemon drops privileges, it inadvertently changes the ownership of the pointed-to file to the daemon user, enabling unauthorized access or modification of sensitive system files. This vulnerability poses a significant risk for privilege escalation on systems where MRTG is deployed with elevated startup permissions.

## Impact

Successful exploitation allows a local, non-root user to gain control over arbitrary files on the filesystem by modifying their ownership. This can lead to full compromise of sensitive configuration files, shadow passwords, or system binaries, effectively escalating privileges to that of the daemon account or higher, depending on the files targeted.

## Recommendation

- Monitor for symlink creation in directories where MRTG writes its PID files.
- Audit existing MRTG deployments to ensure the daemon is not configured to run in ways that permit user-level control over its PID directory.
- Restrict the ability of low-privileged users to create symlinks in system-critical directories using fs.protected_symlinks kernel parameters.
- Apply patches provided by the vendor when available to address the insecure file path handling.
