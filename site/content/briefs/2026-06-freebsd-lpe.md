---
title: Multiple Privilege Escalation Vulnerabilities in FreeBSD (CVE-2026-45257, CVE-2026-49413)
slug: 2026-06-freebsd-lpe
description: Multiple vulnerabilities, including CVE-2026-45257 (kernel out-of-bounds write) and CVE-2026-49413 (Linux compatibility layer memory mapping), exist in FreeBSD branches 14 and 15, allowing a local unprivileged attacker to achieve privilege escalation.
date: "2026-06-14T09:13:46Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - freebsd
  - vulnerability
  - privilege-escalation
  - local-privilege-escalation
vendors:
  - FreeBSD
products:
  - FreeBSD branch 14 versions prior to 14-n274315
  - FreeBSD branch 14.3 versions prior to 14.3-n271519
  - FreeBSD branch 14.4 versions prior to 14.4-n273719
  - FreeBSD branch 15 versions prior to 15-n283886
  - FreeBSD branch 15.0 versions prior to 15.0-n281057
  - FreeBSD branch 15.1 versions prior to 15.1-n283555
affected_os:
  - FreeBSD
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0716/
  - https://www.freebsd.org/security/advisories/FreeBSD-SA-26:26.ktls.asc
  - https://www.freebsd.org/security/advisories/FreeBSD-SA-26:30.linux.asc
  - https://www.cve.org/CVERecord?id=CVE-2026-45257
  - https://www.cve.org/CVERecord?id=CVE-2026-49413
iocs:
  - type: url
    value: https://www.freebsd.org/security/advisories/FreeBSD-SA-26:26.ktls.asc
  - type: url
    value: https://www.freebsd.org/security/advisories/FreeBSD-SA-26:30.linux.asc
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-45257
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-49413
ioc_counts:
  url: 4
rules:
  - title: Detects FreeBSD Privilege Escalation - Root Shell from Suspicious Context
    description: Detects a shell process (e.g., sh, bash, zsh) running with effective UID 0 (root) that is spawned from an unusual or unprivileged parent process, indicating successful local privilege escalation (e.g., via CVE-2026-45257 or CVE-2026-49413).
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - freebsd
  - title: Detects FreeBSD Execution from Suspicious User-Writable Directories with Elevated Privileges
    description: Detects executable processes running with root privileges that originate from common user-writable directories like /tmp, /var/tmp, or /dev/shm. This can indicate successful local privilege escalation where an attacker drops and executes a payload (e.g., via CVE-2026-45257 or CVE-2026-49413).
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1033
      - T1068
    data_sources:
      - process_creation
      - freebsd
  - title: Detects FreeBSD Modification of Critical Authentication Files
    description: Detects attempts to modify critical authentication and authorization files (e.g., /etc/passwd, /etc/shadow, /etc/sudoers) on FreeBSD systems. Such modifications are often indicators of successful privilege escalation or account tampering, potentially as a post-exploitation activity of vulnerabilities like CVE-2026-45257 or CVE-2026-49413.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
      - privilege_escalation
    techniques:
      - T1098
    data_sources:
      - file_event
      - freebsd
rules_count: 3
---

CERT-FR has issued an advisory regarding multiple privilege escalation vulnerabilities discovered in FreeBSD. These vulnerabilities, identified as CVE-2026-45257 and CVE-2026-49413, affect various versions across FreeBSD branches 14 and 15. CVE-2026-45257 involves an out-of-bounds write in the `rt_ktls_init_key` and `rt_ktls_set_key` functions within the kernel's network routing code, while CVE-2026-49413 allows a local attacker to map arbitrary physical memory pages via the Linux compatibility layer. Successful exploitation grants a local, unprivileged attacker root privileges on the compromised system, enabling them to bypass security controls, exfiltrate data, or establish persistence. It is crucial for defenders to patch affected systems immediately to prevent unauthorized access and system compromise.

## Attack Chain

1.  **Initial Access**: A local unprivileged attacker gains or already possesses user-level access to a vulnerable FreeBSD system.
2.  **Vulnerability Trigger (CVE-2026-45257)**: The attacker executes a specially crafted program that interacts with the kernel's routing table, specifically targeting the `rt_ktls_init_key` or `rt_ktls_set_key` functions to trigger an out-of-bounds write.
3.  **Vulnerability Trigger (CVE-2026-49413)**: The attacker utilizes the Linux compatibility layer to perform malformed memory mapping operations, allowing them to map arbitrary physical memory pages into their process address space.
4.  **Kernel Primitive Acquisition**: Successful exploitation of either vulnerability provides the attacker with a powerful kernel primitive, such as arbitrary kernel memory read/write capabilities or kernel code execution.
5.  **Privilege Escalation**: The attacker leverages the kernel primitive to modify their process's credentials, effectively elevating their user ID (UID) and effective user ID (EUID) to `0` (root).
6.  **Root Shell / Arbitrary Command Execution**: With root privileges, the attacker typically spawns a root shell (e.g., `/bin/sh`) or executes arbitrary commands as the `root` user.
7.  **Post-Exploitation Activity**: The attacker proceeds with actions such as disabling security measures, installing backdoors, exfiltrating sensitive data, or deploying additional malicious payloads.

## Impact

The successful exploitation of these privilege escalation vulnerabilities allows a local attacker to gain full control over the affected FreeBSD system. This can lead to complete system compromise, enabling the attacker to access, modify, or delete any data, install malware, create new privileged user accounts, or completely disable the system. For organizations, this translates to severe data breaches, disruption of critical services, and potential regulatory non-compliance. While specific victim counts are not provided, any unpatched FreeBSD system is at risk.

## Recommendation

*   Immediately apply the security updates provided by FreeBSD for the affected versions mentioned in the FreeBSD security advisories CVE-2026-45257 and CVE-2026-49413.
*   Deploy the Sigma rules in this brief to your SIEM and tune them for your environment to detect post-exploitation activity.
*   Enable comprehensive `process_creation` and `file_event` logging on FreeBSD systems to allow for detection of suspicious activity by the provided Sigma rules.
*   Review access controls and ensure that only trusted users have local access to FreeBSD systems, reducing the attack surface for local privilege escalation.
