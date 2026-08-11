---
title: AMD Display Driver Kernel Deadlock Vulnerability
slug: 2026-08-amd-display-deadlock
description: CVE-2026-68364 identifies a deadlock vulnerability in the AMD Linux kernel display driver's dc_lock mechanism during suspend, potentially enabling a local denial-of-service.
date: "2026-08-11T10:04:57Z"
type: threat
types:
  - threat
severities:
  - low
exploited: true
vendors:
  - AMD
products:
  - display controller driver
cves:
  - id: CVE-2026-68364
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68364
action_plan:
  priority: monitor_or_close
  owners:
    - IT Operations
  mitigation_plan:
    - priority: medium_term
      action: Update Linux kernel to the version containing the fix for CVE-2026-68364
      owner: IT Operations
      addresses: CVE-2026-68364
      evidence: MSRC security update guide
---

The Microsoft Security Response Center has disclosed CVE-2026-68364, a vulnerability within the Linux kernel AMD display driver (drm/amd/display). The issue resides in the ISM dc_lock mechanism, which is responsible for managing display controller locking during system suspend operations. Due to a flaw in the locking logic, a race condition or improper handling during the power management state transition can lead to a deadlock. This vulnerability affects the stability of the kernel, potentially resulting in a denial-of-service (DoS) condition where the display subsystem or the entire system becomes unresponsive. Defenders should note that this is a kernel-level stability issue rather than an exploit involving remote code execution or unauthorized access. Patching involves updating the Linux kernel to the version containing the official fix.

## Impact

Successful triggering of this deadlock vulnerability results in a system hang or denial-of-service on hardware utilizing the affected AMD display drivers. The impact is primarily local, affecting systems running Linux kernels with the vulnerable display driver stack. This vulnerability poses a risk to system uptime and availability in environments where frequent power state transitions (suspend/resume) occur. There is no evidence of active exploitation documented in the disclosure.

## Recommendation

Prioritize patching Linux kernel packages provided by your distribution or hardware vendor to the versions that include the fix for CVE-2026-68364. Ensure kernel update management processes are configured to apply security-related kernel updates across all Linux endpoints utilizing AMD graphics hardware.
