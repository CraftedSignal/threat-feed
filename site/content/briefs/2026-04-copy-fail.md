---
title: Local Privilege Escalation Vulnerability 'Copy Fail' in Linux Kernel
slug: 2026-04-copy-fail
description: A local privilege escalation vulnerability, dubbed 'Copy Fail' (CVE-2026-31431), affects Linux kernels released since 2017, allowing an unprivileged local attacker to gain root permissions by exploiting a logic bug in the authencesn cryptographic template.
date: "2026-04-30T13:54:47Z"
type: threat
types:
  - threat
severities:
  - critical
actors:
  - Theori
tags:
  - privilege-escalation
  - linux
  - vulnerability
vendors:
  - Theori
  - Ubuntu
  - Amazon
  - Red Hat
  - SUSE
  - Linux
products:
  - Linux kernel
  - Ubuntu 24.04 LTS
  - Amazon Linux 2023
  - RHEL 10.1
  - SUSE 16
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-31431
    cvss: 7.8
    epss: 8e-05
references:
  - https://www.bleepingcomputer.com/news/security/new-linux-copy-fail-flaw-gives-hackers-root-on-major-distros/
rules:
  - title: Detect Suspicious Splice Usage for Privilege Escalation
    description: Detects suspicious usage of the splice() system call potentially related to privilege escalation attempts like Copy Fail (CVE-2026-31431), monitoring for file modifications in common temporary directories followed by process execution.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
      - T1548.001
    data_sources:
      - process_creation
      - linux
  - title: Detect algif_aead module removal
    description: Detects attempts to remove the 'algif_aead' module, which is a recommended mitigation for CVE-2026-31431.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A local privilege escalation vulnerability, "Copy Fail" (CVE-2026-31431), impacts Linux kernels released since 2017. Discovered by Theori's AI-driven pentesting platform Xint Code, the vulnerability allows an unprivileged local attacker to gain root permissions. Theori reported the finding to the Linux kernel security team on March 23, 2026, and patches became available within a week. A proof-of-concept exploit was published, demonstrating a 732-byte script that can root every Linux distribution shipped since 2017. This vulnerability stems from a logic bug in the Linux kernel's authencesn cryptographic template. Theori demonstrated successful exploits on Ubuntu 24.04, Amazon Linux 2023, RHEL 10.1, and SUSE 16.

## Attack Chain

1. An unprivileged local attacker gains access to a vulnerable Linux system.
2. The attacker utilizes the `AF_ALG` socket-based interface to access Linux kernel crypto functions from user space.
3. The attacker uses the `splice()` system call to perform a controlled 4-byte write in the page cache of a readable file, instead of a normal buffer.
4. The attacker targets a setuid-root binary file for modification.
5. The 4-byte write alters the behavior of the setuid-root binary.
6. The attacker executes the modified setuid-root binary.
7. Due to the altered behavior, the binary grants the attacker elevated privileges.
8. The attacker gains root privileges on the system.

## Impact

Successful exploitation of the Copy Fail vulnerability (CVE-2026-31431) allows an unprivileged local attacker to gain root privileges on a vulnerable Linux system. Theori demonstrated and confirmed the exploit on Ubuntu 24.04, Amazon Linux 2023, RHEL 10.1, and SUSE 16, highlighting the widespread impact. Multi-tenant Linux hosts, Kubernetes/container clusters, CI runners/build farms, and cloud SaaS environments running user code are at high risk.

## Recommendation

*   Apply available kernel patches for CVE-2026-31431 on affected Linux distributions, prioritizing multi-tenant environments (e.g., Ubuntu 24.04 LTS, Amazon Linux 2023, RHEL 10.1, SUSE 16).
*   As an interim mitigation, disable the vulnerable crypto interface by blocking `AF_ALG` socket creation or disabling the `algif_aead` module, as described in the overview.
*   Monitor for the execution of unusual processes after the modification of binaries in `/tmp` or `/var/tmp` using the Sigma rule "Detect Suspicious Splice Usage for Privilege Escalation".
*   Deploy the Sigma rule "Detect algif_aead module removal" to detect attempts to disable the vulnerable module.
