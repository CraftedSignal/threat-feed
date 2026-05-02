---
title: CVE-2026-31431 'Copy Fail' Linux Kernel Privilege Escalation
slug: 2026-05-copy-fail
description: The 'Copy Fail' vulnerability (CVE-2026-31431) in the Linux kernel allows a local attacker to escalate privileges to root, potentially leading to container breakout and lateral movement in cloud environments.
date: "2026-05-02T03:06:08Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - privilege-escalation
  - linux
  - kernel
vendors:
  - Red Hat
  - SUSE
  - Ubuntu
  - AWS
  - Debian
  - Fedora
products:
  - Amazon Linux 2023
  - Red Hat Enterprise Linux (RHEL 10.1)
  - SUSE 16
  - Ubuntu 24.04 LTS
affected_os:
  - linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-31431
    cvss: 7.8
    epss: 9e-05
references:
  - https://www.microsoft.com/en-us/security/blog/2026/05/01/cve-2026-31431-copy-fail-vulnerability-enables-linux-root-privilege-escalation/
  - https://nvd.nist.gov/vuln/detail/CVE-2026-31431
  - https://www.cisa.gov/news-events/alerts/2026/05/01/cisa-adds-one-known-exploited-vulnerability-catalog
rules:
  - title: Detect Execution from /tmp
    description: Detects execution of binaries from /tmp, which can indicate exploit activity.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious AF_ALG Socket Creation
    description: Detects the creation of AF_ALG sockets, potentially indicating exploit attempts related to CVE-2026-31431.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-31431, known as "Copy Fail," is a high-severity local privilege escalation vulnerability affecting the Linux kernel's cryptographic subsystem. The vulnerability resides within the algif_aead module of the AF_ALG (userspace crypto API) and results from improper memory handling during in-place operations. An unprivileged user can exploit this flaw to corrupt the cache of readable files, including setuid binaries, resulting in unauthorized root privilege escalation. This vulnerability impacts a wide range of Linux distributions, including Ubuntu 24.04 LTS, Amazon Linux 2023, Red Hat Enterprise Linux (RHEL 10.1), and SUSE 16, as well as other distributions like Debian, Fedora, and Arch Linux. The availability of a working proof-of-concept exploit has raised concerns about potential widespread exploitation, leading to its addition to the CISA KEV catalog.

## Attack Chain

1.  **Reconnaissance:** The attacker gains limited visibility into the environment (e.g., compromised CI runner, web container) and identifies the kernel version. Kernel version information is obtained without elevated privileges.
2.  **Script Execution:** The attacker executes a compact Python script that interacts with standard kernel interfaces, without relying on networking, compilation, or third-party libraries.
3.  **AF_ALG Abuse:** The script abuses an interaction between the AF_ALG (asynchronous crypto) socket interface, the splice() system call and improper error handling during a failed copy operation.
4.  **Kernel Page Cache Corruption:** This interaction leads to a controlled 4-byte overwrite in the kernel page cache, corrupting sensitive kernel-managed data.
5.  **Privilege Escalation:** By corrupting kernel structures associated with credentials or execution context, the attacker escalates their process to UID 0.
6.  **Boundary Breach:** The system's privilege boundary is broken, neutralizing SELinux/AppArmor protections, and bypassing local security controls.
7.  **Lateral Movement/Container Escape:** The attacker can now use the root privileges gained to perform lateral movement or escape the container.

## Impact

Successful exploitation of CVE-2026-31431 leads to full root privilege escalation, resulting in high impact to confidentiality, integrity, and availability. This could facilitate container breakout, multi-tenant compromise, and lateral movement within shared environments. The vulnerability's reliability, stealth (in-memory-only modification), and cross-platform applicability make it particularly dangerous in cloud, CI/CD, and Kubernetes environments.

## Recommendation

*   Identify all instances of affected products and versions in your environment and prioritize patching (CVE-2026-31431).
*   Deploy the Sigma rule for suspicious process execution under /tmp, often used in exploit PoCs, and tune for your environment.
*   Monitor for suspicious AF_ALG socket creation events, as indicated in the Attack Chain, using the provided Sigma rule.
*   If patches are unavailable, consider implementing network isolation and access controls as interim mitigation measures.
