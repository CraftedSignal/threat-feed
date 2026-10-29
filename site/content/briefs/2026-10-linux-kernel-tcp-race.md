---
brief_id: brief-2026-10-29-linux-kernel-tcp-race
event_id: brief-2026-10-29-linux-kernel-tcp-race
revision: 1
activity_at: "2026-10-29T17:30:03Z"
title: 'Linux Kernel: TCP IPv4 race condition memory corruption (CVE-2026-98432)'
slug: 2026-10-linux-kernel-tcp-race
description: A race condition in the Linux kernel IPv4 TCP handshake allows remote unauthenticated attackers to trigger a use-after-free, potentially leading to kernel memory corruption or root code execution.
date: "2026-10-29T17:30:03Z"
type: threat
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
affected_os:
  - Linux
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
    epss: 0.00388
    kev_status: "false"
references:
  - https://thehackernews.com/2026/10/linux-kernel-tcp-flaw-with-98-cvss.html
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
