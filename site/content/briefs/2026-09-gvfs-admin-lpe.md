---
title: Local Privilege Escalation in gvfsd-admin via TOCTOU Race Condition
slug: 2026-09-gvfs-admin-lpe
description: A Time-of-Check Time-of-Use (TOCTOU) race condition in the gvfsd-admin daemon allows local attackers to perform privilege escalation by manipulating symbolic links to modify ownership of arbitrary system files.
date: "2026-09-10T17:07:27Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:gnome:gvfs:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - linux
  - gnome
vendors:
  - GNOME
products:
  - gvfs
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This allows an authenticated local attacker to modify critical system files, leading to a full local privilege escalation to root.
    confidence_band: high
cves:
  - id: CVE-2026-88924
    cvss: 7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-88924
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch gvfs to the vendor-recommended version once available
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-88924 remediation
  mitigation_plan:
    - priority: immediate
      action: Monitor for unexpected symlink creation in gvfs-related temporary directories
      owner: SOC
      addresses: CVE-2026-88924
      evidence: TOCTOU race condition methodology
---

CVE-2026-88924 describes a vulnerability in the admin backend of the GNOME Virtual File System (gvfs), specifically within the privileged gvfsd-admin daemon. The daemon is responsible for managing private D-Bus sockets and improperly handles ownership changes for these sockets. By calling a link-following chown() function on a pathname located within a user-controlled directory, the daemon becomes susceptible to a TOCTOU race condition. An authenticated local attacker can monitor the creation of the socket and replace the expected socket path with a symbolic link pointing to a sensitive root-owned file, such as /etc/pam.d/su. Because the daemon follows the symbolic link during the ownership change, it inadvertently changes the ownership of the target file to the attacker, providing the attacker with write access to root-controlled system configurations. This vulnerability enables a complete local privilege escalation to root.

## Attack Chain

1. The attacker monitors the file system for the creation of new D-Bus sockets by gvfsd-admin within a user-accessible directory.
2. The attacker identifies the specific directory path where gvfsd-admin will create the temporary socket.
3. The attacker anticipates the timing of the chown() call by the privileged daemon.
4. The attacker quickly removes or moves the temporary socket file created by the daemon.
5. The attacker replaces the socket path with a symbolic link targeting a sensitive system file (e.g., /etc/shadow or /etc/pam.d/su).
6. The gvfsd-admin daemon follows the malicious symlink and executes chown() on the target file.
7. The attacker gains ownership of the target root-owned file.
8. The attacker modifies the system file to insert a back door, change credentials, or execute arbitrary code with root privileges.

## Impact

Successful exploitation allows an authenticated local user to gain full root privileges on systems running affected versions of gvfs. By modifying critical files like /etc/pam.d/su or /etc/passwd, an attacker can bypass authentication, create unauthorized administrative accounts, or execute persistent malicious code at the highest privilege level, effectively compromising the integrity and security of the entire operating system.

## Recommendation

Prioritize the application of patches for CVE-2026-88924 as provided by the GNOME project or relevant Linux distribution maintainers. Ensure that all systems are updated to the fixed versions of gvfs. In the absence of a patch, limit local user access to the system, as the exploit requires an authenticated local session.
