---
brief_id: brief-2026-11-05-linux-kernel-key-uaf
event_id: brief-2026-11-05-linux-kernel-key-uaf
revision: 1
activity_at: "2026-11-05T15:58:01Z"
title: 'Linux Kernel: Use-after-free in keyctl_describe_key (CVE-2026-99224)'
slug: 2026-11-linux-kernel-key-uaf
description: A race condition in the Linux kernel key management subsystem allows a use-after-free vulnerability during key description retrieval, potentially resulting in kernel-mode page faults.
date: "2026-11-05T15:58:01Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*
vendors:
  - Linux
products:
  - Linux kernel (all versions prior to fix)
cves:
  - id: CVE-2026-99224
    cvss: 7
    epss: 0.00119
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-99224
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Linux kernel once upstream fix is integrated into distribution-specific kernels
      owner: IT Operations
      due: Asap upon availability
      evidence: CVE-2026-99224 fix details in kernel source
  hunt_leads:
    - lead: Monitor system logs for page fault occurrences involving kernel-mode string formatting functions
      data_needed:
        - dmesg
        - auditd logs
      priority: medium
      confidence: medium
      disposition: monitor_or_close
      evidence: 'The source documentation provides a specific oops report: BUG: unable to handle page fault for address'
  mitigation_plan:
    - priority: immediate
      action: Identify and update kernel environments running vulnerable modules such as af_rxrpc
      owner: IT Operations
      addresses: CVE-2026-99224
      evidence: The source notes that AF_RXRPC=m can facilitate the race condition
---

CVE-2026-99224 is a vulnerability in the Linux kernel key management subsystem. Specifically, the function keyctl_describe_key fails to properly pin the memory associated with a key type's name during the formatting process. If a module providing a key type is unloaded concurrently with a key description request, the kernel may attempt to access memory from the released module, leading to a use-after-free condition and a potential kernel panic or page fault.

## Impact

Successful exploitation of this race condition can cause a kernel-mode page fault. In a local context, this can lead to a system crash (Denial of Service). While the provided information focuses on the crash, the access to freed memory storage suggests potential for further memory corruption depending on system state.

## Recommendation

1. Identify systems running Linux kernel versions susceptible to this race condition.
2. Monitor kernel logs (dmesg) for page fault errors related to memory addresses within loaded modules, particularly involving key management operations.
3. Patch the Linux kernel to the version containing the fix for CVE-2026-99224 once the stable release becomes available from your distribution vendor.
