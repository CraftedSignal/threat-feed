---
brief_id: brief-2026-10-29-linux-kernel-tcp-race
event_id: brief-2026-10-29-linux-kernel-tcp-race
revision: 9
activity_at: "2026-11-07T03:57:28Z"
revision_history:
  - revision: 2
    at: "2026-10-31T00:05:24Z"
    checksum: sha256:690a10034fc434e0175c49d030c3b7833b6cb5dec19bfe83a31c356ad1441968
    summary: ubuntu version 22.04, 24.04, 26.04, 26.10
    changed_fields:
      - affected_products
      - claim_state
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://pwn.watch/i/linux-kernel-ipv4-tcp-uaf-cve-2026-98432
  - revision: 3
    at: "2026-10-31T03:05:09Z"
    checksum: sha256:46457265ff14daf6ff319714fa7f488fbd36d845b689ed7246ccc49c8e196293
    summary: debian version 12, 13; linux kernel version 4.4 and later stable branches
    changed_fields:
      - affected_products
      - lastmod
      - updates
    source_urls:
      - https://pwn.watch/i/linux-kernel-ipv4-tcp-uaf-cve-2026-98432
  - revision: 4
    at: "2026-11-01T02:33:11Z"
    checksum: sha256:2986c0ab8c317f20247b57c3c9e4e8fd50de3b87b1401fa0dab0263f0b8e34fb
    summary: new product
    changed_fields:
      - affected_products
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://pwn.watch/i/linux-kernel-ipv4-tcp-uaf-cve-2026-98432
  - revision: 5
    at: "2026-11-04T10:01:07Z"
    checksum: sha256:54f09092dfde5030789c58b41feb5d269ca571ee1c77cdd3d6ef2dfb7071b8b7
    summary: amazon linux version 2, 2023
    changed_fields:
      - affected_products
      - claim_state
      - cves
      - lastmod
      - updates
    source_urls:
      - https://pwn.watch/i/linux-kernel-ipv4-tcp-uaf-cve-2026-98432
  - revision: 6
    at: "2026-11-05T03:12:34Z"
    checksum: sha256:3d803836b4d1c994faf508f0b27c255804d07bc6825fd294c4fa858bb3c7d979
    summary: OS rhel 10; OS ubuntu 18.04; OS ubuntu 20.04; OS ubuntu 26.04; OS amazon linux 2023; OS rhel 8; OS rhel 9; OS ubuntu 16.04; OS ubuntu 22.04; OS ubuntu 24.04; OS amazon linux 2
    changed_fields:
      - affected_os
      - affected_products
      - cves
      - lastmod
      - updates
    source_urls:
      - https://pwn.watch/i/linux-kernel-ipv4-tcp-uaf-cve-2026-98432
  - revision: 7
    at: "2026-11-05T14:42:05Z"
    checksum: sha256:84dfb699b774b16280137d622578518cce7db1dbe7a2435a1c9ad97bc223c6d9
    summary: poc_available
    changed_fields:
      - cves
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=7C378158-FB79-5ABF-9AFD-6136E42E3FE8&utm_source=rss&utm_medium=rss
  - revision: 8
    at: "2026-11-07T02:48:39Z"
    checksum: sha256:d4f371a8bdeff769e578c409ac7197817b31a2f2bb2beee123a7228eedeaccff
    summary: new product
    changed_fields:
      - affected_products
      - lastmod
      - updates
    source_urls:
      - https://pwn.watch/i/linux-kernel-ipv4-tcp-uaf-cve-2026-98432
  - revision: 9
    at: "2026-11-07T03:57:28Z"
    checksum: sha256:c8a2130096de849fa53fd15483860e505bb4f5652872e55eaadf9d43b025f21c
    summary: new product
    changed_fields:
      - affected_products
      - lastmod
      - references
      - updates
    source_urls:
      - https://pwn.watch/i/linux-kernel-ipv4-tcp-uaf-cve-2026-98432
title: 'Linux Kernel: TCP IPv4 race condition memory corruption (CVE-2026-98432)'
slug: 2026-10-linux-kernel-tcp-race
description: A race condition in the Linux kernel IPv4 TCP handshake allows remote unauthenticated attackers to trigger a use-after-free, potentially leading to kernel memory corruption or root code execution.
date: "2026-10-29T17:30:03Z"
lastmod: "2026-11-07T03:56:50Z"
type: threat
claim_state: verified
types:
  - threat
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=7C378158-FB79-5ABF-9AFD-6136E42E3FE8&utm_source=rss&utm_medium=rss
tags:
  - vulnerability
  - linux
  - kernel
vendors:
  - Canonical
  - Red Hat
  - Amazon
  - Oracle
  - SUSE
  - Debian
products:
  - Linux kernel (>= 4.4)
  - Ubuntu
  - Red Hat Enterprise Linux
  - Amazon Linux
  - Oracle Linux
  - SUSE Linux Enterprise Server
  - Debian
  - Linux kernel
  - Ubuntu (22.04, 24.04, 26.04, 26.10)
  - Linux kernel (4.4 and later stable branches)
  - Debian (12, 13)
  - Linux kernel (>= 4.4, < 7.3)
  - Linux kernel (<= 7.2)
  - Amazon Linux (2, 2023)
  - SUSE Linux Enterprise
  - Linux kernel (>= 4.4, < various fixed versions)
  - Ubuntu (22.04, 24.04, 26.04)
  - Linux kernel (4.4 - <7.3)
  - Ubuntu (22.04 LTS, 24.04 LTS, 26.04 LTS, 26.10)
affected_os:
  - Linux
  - RHEL 8
  - RHEL 9
  - RHEL 10
  - Ubuntu 16.04
  - Ubuntu 18.04
  - Ubuntu 20.04
  - Ubuntu 22.04
  - Ubuntu 24.04
  - Ubuntu 26.04
  - Amazon Linux 2
  - Amazon Linux 2023
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The exploit uses the flaw to let a remote attacker with no credentials run commands as root on Linux servers.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: When the kernel calls that pointer, the payload executes a shell command of the attacker choice as root.
    confidence_band: high
cves:
  - id: CVE-2026-98432
    cvss: 9.8
    epss: 0.0076
    kev_status: "false"
references:
  - https://thehackernews.com/2026/10/linux-kernel-tcp-flaw-with-98-cvss.html
  - https://pwn.watch/i/linux-kernel-ipv4-tcp-uaf-cve-2026-98432
  - https://github.com/H1z3-br0/CVE-2026-98432
  - https://www.openwall.com/lists/oss-security/2026/10/30/1
  - https://nvd.nist.gov/vuln/detail/CVE-2026-98432
  - https://osv.dev/vulnerability/CVE-2026-98432
  - https://git.kernel.org/stable/c/11a03ce3c4a62d84c10ccdfe47f8075006498568
  - https://www.anthropic.com/research/discovering-vulnerabilities-with-claude
  - https://status.linode.com/incidents/nt58zhx3pmgm
  - https://access.redhat.com/security/vulnerabilities/RHSB-2026-016
  - https://almalinux.org/blog/2026-10-30-cve-2026-98432/
  - https://github.com/lightningnetwork/lnd/releases/tag/v0.20.7-beta
  - https://aws.amazon.com/security/security-bulletins/2026-160-aws/
  - https://sploitus.com/exploit?id=7C378158-FB79-5ABF-9AFD-6136E42E3FE8&utm_source=rss&utm_medium=rss
  - https://launchpad.net/ubuntu/+source/linux/6.8.0-149.149
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch all Linux distributions where vendor kernels are available (Debian, Oracle Linux, SUSE, Amazon Linux).
      owner: IT Operations
      due: 48h
      evidence: Source provides list of fixed package/advisory references for these distributions.
  hunt_leads:
    - lead: Identify repeated, failed TCP connection attempts from single source IPs targeted at high-value servers.
      technique_id: T1068
      data_needed:
        - Firewall logs
        - Kernel audit logs
        - Application connection logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability relies on winning a race condition, requiring multiple connection requests to succeed.
  mitigation_plan:
    - priority: immediate
      action: Monitor system logs for repeated kernel panics or unexplained service restarts.
      owner: SOC
      addresses: CVE-2026-98432
      evidence: A lost race could result in a system crash.
updates:
  - at: "2026-11-04T10:00:34Z"
    level: L2
    summary: amazon linux version 2, 2023
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/linux-kernel-ipv4-tcp-uaf-cve-2026-98432
  - at: "2026-11-05T03:12:00Z"
    level: L1
    summary: OS rhel 10; OS ubuntu 18.04; OS ubuntu 20.04; OS ubuntu 26.04; OS amazon linux 2023; OS rhel 8; OS rhel 9; OS ubuntu 16.04; OS ubuntu 22.04; OS ubuntu 24.04; OS amazon linux 2
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/linux-kernel-ipv4-tcp-uaf-cve-2026-98432
  - at: "2026-11-05T14:39:39Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=7C378158-FB79-5ABF-9AFD-6136E42E3FE8&utm_source=rss&utm_medium=rss
  - at: "2026-11-07T02:48:06Z"
    level: L1
    summary: new product
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/linux-kernel-ipv4-tcp-uaf-cve-2026-98432
  - at: "2026-11-07T03:56:50Z"
    level: L1
    summary: new product
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/linux-kernel-ipv4-tcp-uaf-cve-2026-98432
---

CVE-2026-98432 is a use-after-free vulnerability in the Linux kernel's IPv4 TCP connection handling code, introduced in kernel version 4.4. A race condition occurs during the handshake process when IP options are processed; if a socket is destroyed while another CPU is processing IP options for a resent connection request, the kernel accesses freed memory. Anthropic demonstrated a proof-of-concept exploit path that uses this race condition to leak kernel memory (bypassing KASLR) and eventually achieve arbitrary code execution as root. As of October 29, 2026, no in-the-wild exploitation has been observed. Fixes are available for some distributions, while others (notably Ubuntu and RHEL) are still developing or testing patches.

## Attack Chain
1. Attacker sends a TCP connection request with specific IP options (Record Route or Timestamp).
2. Attacker resends the request to trigger the race condition during the TCP handshake.
3. Kernel prematurely frees memory associated with pending IP options while a second CPU attempts to read them.
4. Attacker forces the kernel to return the freed memory to the attacker, leaking kernel addresses.
5. Attacker utilizes leaked addresses to bypass KASLR.
6. Attacker triggers the race condition again to overwrite a callback pointer in kernel memory.
7. Kernel executes the attacker-controlled payload during pointer invocation.
8. Attacker gains root command execution.

## Impact
The vulnerability allows for potential remote unauthenticated kernel memory corruption, system crashes, or arbitrary code execution with root privileges. Success depends on the attacker winning a race condition, which may require multiple connection attempts.

## Recommendation
- Inventory all Linux-based servers to identify kernels running versions affected by CVE-2026-98432.
- Apply vendor-specific kernel updates as soon as they become available for your distribution.
- For custom kernel builds, update to patched versions: 5.10.272, 5.15.223, 6.1.190, 6.6.159, 6.12.113, 6.18.56, 7.2.10, or 7.3.
- Monitor for unusual kernel crashes (dmesg, /var/log/kern.log) that may indicate failed exploitation attempts.
