---
brief_id: brief-2026-10-23-linux-kernel-lpe
event_id: brief-2026-10-23-linux-kernel-lpe
revision: 6
activity_at: "2026-11-04T00:26:49Z"
revision_history:
  - revision: 2
    at: "2026-10-29T15:53:38Z"
    checksum: sha256:b87fb5e12ec4b97f98702f6af58ad509cad83fe38a7198dbd79be185e7540d08
    summary: severity → critical; added CVE-2026-98432
    changed_fields:
      - action_plan
      - affected_products
      - affected_vendors
      - cves
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - references
      - severity
      - tags
      - ttps
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=6854C6B5-0F5C-5F26-B4EF-B42BD296BCAE&utm_source=rss&utm_medium=rss
  - revision: 3
    at: "2026-11-02T08:30:46Z"
    checksum: sha256:c7d056dd9823cf5491a62674534ff42b3c30dd021b514b560098f315c28bbee6
    summary: added coverage for Linux Kernel (< 7.2)
    changed_fields:
      - action_plan
      - affected_products
      - cves
      - lastmod
      - references
      - tags
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=C3DF6930-14F1-5C24-98BA-CE5CC970EC12&utm_source=rss&utm_medium=rss
  - revision: 4
    at: "2026-11-02T17:55:48Z"
    checksum: sha256:570f417c138266311302f26036f63fe752914f4cd1119e7b85a3e48002e5dadb
    summary: added CVE-2026-99224
    changed_fields:
      - action_plan
      - affected_products
      - cpes
      - cves
      - exploitation_evidence
      - lastmod
      - priority_signals
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-99224
  - revision: 5
    at: "2026-11-02T21:55:15Z"
    checksum: sha256:1f00422c6ba35499aa5c8fc5177833b20d196c182efa676d7fea3082e2e2997e
    summary: added coverage for Linux Kernel
    changed_fields:
      - action_plan
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-58826
  - revision: 6
    at: "2026-11-04T00:26:49Z"
    checksum: sha256:d450c38000aca146617c96c0ef53be7267ca8cc25e0d6df5a1ad67836794502a
    summary: added coverage for Linux kernel (CVE-2026-99264)
    changed_fields:
      - action_plan
      - affected_products
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-99264
title: 'Linux Kernel: io_uring privilege escalation (CVE-2024-0582)'
slug: 2026-10-linux-kernel-lpe
description: CVE-2024-0582 is a privilege escalation vulnerability in the Linux kernel io_uring subsystem that enables unauthorized write access to /etc/passwd via a Dirty Cred technique.
date: "2026-10-23T19:48:50Z"
lastmod: "2026-11-04T00:24:39Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: not_observed
source_assessment:
  reliability: B
  credibility: "3"
  rating: B3
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:6.7:*:*:*:*:*:*:*
  - cpe:2.3:a:linux:kernel:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - linux
  - kernel
  - io_uring
  - vulnerability
  - remote-code-execution
  - cve-2026-98432
  - use-after-free
vendors:
  - Linux
products:
  - Linux Kernel (< 6.6.5, 6.7)
  - Linux Kernel (>= 4.4)
  - Linux Kernel (< 7.2)
  - Linux kernel
  - Linux kernel (CVE-2026-99264)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The exploit implements a Dirty Cred attack method to gain unauthorized write access to /etc/passwd.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Use-after-free in Linux kernel IPv4 TCP handshake allows remote code execution.
    confidence_band: high
cves:
  - id: CVE-2024-0582
    cvss: 7.8
    epss: 0.12734
    kev_status: "false"
  - id: CVE-2026-98432
    cvss: 9.8
    epss: 0.00388
    kev_status: "false"
  - id: CVE-2026-74583
    cvss: 7.8
    epss: 0.00117
    kev_status: "false"
  - id: CVE-2026-99218
    cvss: 7
    kev_status: "false"
  - id: CVE-2026-99224
    cvss: 7
    kev_status: "false"
  - id: CVE-2026-58826
    cvss: 8.4
    kev_status: "false"
  - id: CVE-2026-99264
    cvss: 7.8
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-KUZEYARDABULUT-CVE-2024-0582
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-KUZEYARDABULUT-CVE-2024-0582&utm_source=rss&utm_medium=rss
  - https://sploitus.com/exploit?id=6854C6B5-0F5C-5F26-B4EF-B42BD296BCAE
  - https://sploitus.com/exploit?id=6854C6B5-0F5C-5F26-B4EF-B42BD296BCAE&utm_source=rss&utm_medium=rss
  - https://git.kernel.org/stable/c/47d7f7051253bdc02b1d245d87e38f16d31a74df
  - https://vulners.com/cve/CVE-2026-74583
  - https://sploitus.com/exploit?id=C3DF6930-14F1-5C24-98BA-CE5CC970EC12
  - https://sploitus.com/exploit?id=C3DF6930-14F1-5C24-98BA-CE5CC970EC12&utm_source=rss&utm_medium=rss
  - https://nvd.nist.gov/vuln/detail/CVE-2026-99218
  - https://nvd.nist.gov/vuln/detail/CVE-2026-99224
  - https://nvd.nist.gov/vuln/detail/CVE-2026-58826
  - https://nvd.nist.gov/vuln/detail/CVE-2026-99264
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
    - Security Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Linux Kernel to a version >= 6.6.5 or 6.7 to address CVE-2024-0582
      owner: IT Operations
      due: 48h
      evidence: Source documentation identifies affected versions < 6.6.5, 6.7
    - action: Patch Linux kernel across all production environments
      owner: IT Operations
      due: 48h
      evidence: Vulnerability requires kernel update for remediation.
    - action: Patch Linux kernel to the identified secure versions or disable unprivileged user namespaces.
      owner: IT Operations
      due: 72h
      evidence: Vulnerability documentation indicates LPE potential on vulnerable versions.
  hunt_leads:
    - lead: Monitor for unauthorized modifications to /etc/passwd
      technique_id: T1068
      data_needed:
        - Auditd /etc/passwd file integrity monitoring logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: 'Exploit targets /etc/passwd to insert a backdoor: evil::0:0:root:/root:/bin/bash'
    - lead: Inspect kernel logs (dmesg/journalctl) for oops or segmentation faults in network-related functions
      technique_id: T1068
      data_needed:
        - Kernel ring buffer (dmesg)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Greps the kernel journal for oops lines that name the functions in the bug call chain.
    - lead: Monitor for suspicious use of unprivileged user namespaces or unusual activity involving network scheduling parameters.
      technique_id: T1068
      data_needed:
        - Auditd/syslog for unprivileged namespace creation
        - Kernel oops logs or KASAN reports in dmesg
      priority: medium
      confidence: medium
      disposition: monitor_or_close
      evidence: The exploit uses unprivileged user namespaces to trigger the race condition.
    - lead: Monitor system logs for recurring kernel panics or oops messages involving try_to_wake_up or pi_lock.
      data_needed:
        - dmesg
        - /var/log/messages
        - /var/log/kern.log
      priority: low
      confidence: low
      disposition: monitor_or_close
      evidence: The thread can exit and be freed in the meantime and try_to_wake_up() takes pi_lock in freed memory.
    - lead: Monitor for system instability or unexpected data corruption in applications using high-performance network I/O via io_uring.
      data_needed:
        - Kernel crash logs (dmesg)
        - Application error logs regarding network buffer inconsistencies
      priority: medium
      confidence: low
      disposition: monitor-only
      evidence: The kernel incorrectly manages partially consumed buffers, leading to data overwrites between competing requests.
  mitigation_plan:
    - priority: short_term
      action: Disable io_uring for unprivileged users via sysctl where applicable (kernel.unprivileged_userns_clone or similar if supported)
      owner: IT Operations
      addresses: CVE-2024-0582
      evidence: Exploit relies on io_uring buffer ring functionality
    - priority: immediate
      action: Restrict network ingress to sensitive TCP listeners using host firewalls
      owner: Security Operations
      addresses: CVE-2026-98432
      evidence: The attack starts with a SYN from the attacker, so a packet dropped before the listener never reaches it.
    - priority: medium
      action: Upgrade the Linux kernel to the version containing the fix for CVE-2026-99218.
      owner: IT Operations
      addresses: CVE-2026-99218
      evidence: Hold rcu across the loop.
    - priority: immediate
      action: Monitor distribution-specific security advisories and apply kernel patches for CVE-2026-58826 as soon as they become available.
      owner: IT Operations
      addresses: CVE-2026-58826
      evidence: This could lead to local escalation of privilege.
    - priority: immediate
      action: Patch the Linux kernel to the version addressing CVE-2026-99264
      owner: IT Operations
      addresses: CVE-2026-99264
      evidence: Vulnerability resolved in Linux kernel io_uring/net subsystem
  gaps:
    - Lack of specific exploit payloads or PoC code to develop a high-confidence signature.
updates:
  - at: "2026-11-02T08:30:02Z"
    level: L2
    summary: added coverage for Linux Kernel (< 7.2)
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=C3DF6930-14F1-5C24-98BA-CE5CC970EC12&utm_source=rss&utm_medium=rss
  - at: "2026-11-02T17:53:59Z"
    level: L2
    summary: added coverage for Linux kernel
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-99218
  - at: "2026-11-02T17:54:06Z"
    level: L2
    summary: added CVE-2026-99224
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-99224
  - at: "2026-11-02T21:54:02Z"
    level: L2
    summary: added coverage for Linux Kernel
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-58826
  - at: "2026-11-04T00:24:39Z"
    level: L2
    summary: added coverage for Linux kernel (CVE-2026-99264)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-99264
---

A proof-of-concept exploit for CVE-2024-0582 has been published, targeting a use-after-free vulnerability within the Linux kernel io_uring subsystem during buffer ring unregistration. The exploit utilizes a "Dirty Cred" approach to corrupt kernel structures, specifically modifying the f_mode flags of file descriptors to grant write access to protected files, including /etc/passwd. Successful exploitation allows a local attacker to escalate privileges to root by injecting a backdoor entry into /etc/passwd.

## Attack Chain
1. Set CPU affinity and raise file descriptor limits to ensure exploit stability.
2. Initialize an io_uring instance and register a buffer ring in kernel memory.
3. Unregister the buffer ring to trigger the use-after-free vulnerability.
4. Perform a file descriptor spray to target the /etc/passwd file descriptor.
5. Corrupt the f_mode flags of the target file descriptor to make /etc/passwd writable.
6. Append a custom root user backdoor entry to /etc/passwd.

## Impact
Successful exploitation grants a local user full root privileges. The exploit requires local access and can be used to bypass system integrity by modifying sensitive configuration files.

## Recommendation
- Audit kernel versions across the environment to identify systems running Linux Kernel versions < 6.6.5 or 6.7.
- Prioritize patching affected Linux kernels to the latest available stable release.
- Deploy monitoring for unauthorized or anomalous modifications to /etc/passwd.
- Restrict the use of io_uring for non-privileged users if the workload allows, as it is a common vector for local privilege escalation.
