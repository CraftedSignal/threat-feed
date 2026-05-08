---
title: Dirty Frag Linux Kernel Local Privilege Escalation Vulnerability
slug: 2026-05-dirty-frag
description: The Dirty Frag vulnerability (CVE-2026-43284 and CVE-2026-43500) is a Linux kernel local privilege escalation that allows an unprivileged local user to gain root privileges by exploiting flaws in the networking subsystem to overwrite protected file contents in the page cache.
date: "2026-05-08T16:28:10Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - linux
  - privilege-escalation
  - vulnerability
  - dirty_frag
vendors:
  - Red Hat
  - Debian
  - Canonical
  - AlmaLinux
  - Amazon
products:
  - Linux kernel
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://ccb.belgium.be/advisories/warning-dirty-frag-new-linux-local-privilege-escalation-vulnerability-was-disclosed
  - https://nvd.nist.gov/vuln/detail/CVE-2026-43284
  - https://nvd.nist.gov/vuln/detail/CVE-2026-43500
  - https://almalinux.org/blog/2026-05-07-dirty-frag/
  - https://aws.amazon.com/security/security-bulletins/rss/2026-027-aws/
  - https://security-tracker.debian.org/tracker/CVE-2026-43284
  - https://access.redhat.com/security/vulnerabilities/RHSB-2026-003
  - https://ubuntu.com/blog/dirty-frag-linux-vulnerability-fixes-available
  - https://www.wiz.io/blog/dirty-frag-linux-kernel-local-privilege-escalation-via-esp-and-rxrpc
  - https://ccb.belgium.be/advisories/warning-copy-fail-getting-root-major-linux-distributions-patch-immediately
rules:
  - title: Detect Potential Dirty Frag Exploitation
    description: Detects CVE-2026-43284 and CVE-2026-43500 exploitation - monitors for suspicious network activity potentially related to the 'Dirty Frag' vulnerability exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - network_connection
      - linux
  - title: Detect Modification of /etc/passwd or /etc/shadow
    description: Detects modification of critical system files /etc/passwd or /etc/shadow, which may indicate a successful privilege escalation attempt after CVE-2026-43284 or CVE-2026-43500 exploitation.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
rules_count: 2
---

The "Dirty Frag" vulnerability, disclosed in May 2026, affects the Linux kernel and allows a local, unprivileged user to escalate privileges to root. The vulnerability chains together two separate kernel flaws within the networking subsystem. Successful exploitation enables attackers to overwrite protected file contents within the Linux page cache, bypassing standard write permission checks. This page cache corruption can be leveraged for deterministic root privilege escalation. The vulnerability belongs to the same class of page-cache corruption issues as Dirty Pipe and "Copy Fail". While an official patched kernel has not been released, most major Linux distributions have backported patches in available updates. No in-the-wild exploitation has been reported, but similar vulnerabilities have been exploited rapidly after disclosure.

## Attack Chain

1.  An unprivileged local user logs into the system, potentially via SSH or a local console.
2.  The attacker exploits the first networking subsystem flaw to create a fragmented network packet.
3.  The attacker exploits the second networking subsystem flaw, triggering improper handling of the fragmented packet.
4.  These flaws allow the attacker to overwrite data in the Linux page cache without proper write permissions.
5.  The attacker targets sensitive files, such as `/etc/passwd` or `/etc/shadow`, within the page cache.
6.  The attacker overwrites the targeted files with malicious content, such as adding a new root user or modifying existing user credentials.
7.  The attacker uses the modified credentials to authenticate as root or escalate privileges to root.
8.  The attacker gains full control of the system, allowing for arbitrary code execution, data exfiltration, and other malicious activities.

## Impact

Successful exploitation of the "Dirty Frag" vulnerability grants an attacker complete control over the affected Linux system. This can lead to data breaches, system downtime, and further propagation of malicious activities within the network. The vulnerability affects a wide range of Linux distributions, potentially impacting a large number of servers, workstations, and embedded devices. Given the CVSS score of 7.8, the impact is considered high due to the potential compromise of confidentiality, integrity, and availability.

## Recommendation

*   Apply available patches from your Linux distribution to address CVE-2026-43284 and CVE-2026-43500 with the highest priority.
*   If patching is not immediately feasible, implement mitigation measures as recommended by your Linux distribution, acknowledging potential impacts on IPSEC and AFS functionality.
*   Deploy the Sigma rule `Detect Potential Dirty Frag Exploitation` to identify suspicious network activity that may indicate an attempted exploitation.
*   Enable auditd logging on Linux systems to capture system calls and file modifications, providing valuable data for incident response and forensic analysis, as required by the Sigma rule.
*   Monitor for unexpected modifications to critical system files such as `/etc/passwd` and `/etc/shadow`, which could indicate successful exploitation.
