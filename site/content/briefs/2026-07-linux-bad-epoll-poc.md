---
title: Proof-of-Concept Exploit Released for Linux 'Bad Epoll' Root Access Vulnerability (CVE-2026-46242)
slug: 2026-07-linux-bad-epoll-poc
description: A publicly available proof-of-concept exploit for CVE-2026-46242, a race-condition use-after-free vulnerability dubbed 'Bad Epoll' in the Linux kernel's `epoll` facility, enables unprivileged processes to gain root privileges on affected Linux and Android systems.
date: "2026-07-06T12:49:19Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*
tags:
  - linux
  - privilege-escalation
  - vulnerability
  - poc
vendors:
  - Linux Foundation
  - Google
products:
  - Linux kernel (6.4 or newer)
  - Pixel 10
affected_os:
  - Linux
  - Android
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Technical details and proof-of-concept (PoC) code targeting a recent Linux kernel vulnerability that could allow unprivileged processes to gain root privileges
    confidence_band: high
cves:
  - id: CVE-2026-46242
    cvss: 7.8
    epss: 0.00124
references:
  - https://www.securityweek.com/proof-of-concept-exploit-released-for-linux-bad-epoll-root-access-vulnerability/
---

A critical privilege escalation vulnerability, tracked as CVE-2026-46242 and dubbed 'Bad Epoll', affects Linux kernel versions 6.4 and newer, including distributions on desktops, servers, and Android phones like the Pixel 10. This flaw is a race-condition use-after-free bug within the `epoll` I/O event notification facility. A proof-of-concept (PoC) exploit, developed by Jaeyoung Chung of Seoul National University, has been publicly released, making the vulnerability significantly easier for attackers to leverage. The PoC demonstrates how an unprivileged process can exploit this bug to leak kernel memory, hijack the CPU's instruction pointer, and execute a Return-Oriented Programming (ROP) chain to gain full root privileges. The issue was introduced in 2023 and, despite an initial attempted fix, required a corrected patch two months after its discovery, highlighting its complexity. Organizations are urged to patch immediately due to the public availability of exploitation tools, which drastically increases the risk of in-the-wild attacks and unauthorized root access.

## Attack Chain

1.  An unprivileged process executes malicious code specifically crafted to exploit CVE-2026-46242.
2.  The malicious code triggers a close-vs-close race condition within the Linux kernel's `epoll` facility's file-release path.
3.  This race condition leads to a use-after-free vulnerability, where one part of the kernel frees an object while another continues to write to it.
4.  The attacker leverages this use-after-free condition to achieve kernel memory leakage.
5.  Using the leaked kernel memory, the attacker hijacks an indirect call to gain control over the CPU's instruction pointer register.
6.  A carefully constructed Return-Oriented Programming (ROP) chain is executed using the controlled instruction pointer.
7.  The ROP chain successfully elevates the privileges of the initially unprivileged process to root.

## Impact

Successful exploitation of the "Bad Epoll" vulnerability results in an unprivileged attacker gaining full root access to the compromised system. This includes Linux desktops, servers, and Android phones running affected kernel versions (6.4 or newer). Root privileges allow the attacker complete control over the operating system, enabling them to install persistent backdoors, exfiltrate sensitive data, modify system configurations, and execute arbitrary code with the highest level of permissions, leading to severe data breaches, system compromise, and potential widespread disruption.

## Recommendation

*   Prioritize patching CVE-2026-46242 on all affected Linux distributions and Android devices running kernel version 6.4 or newer immediately. Refer to your distribution's security advisories for specific patch availability.
*   Regularly apply security updates to all Linux kernel versions, as demonstrated by the complexity and delayed fix of CVE-2026-46242.
