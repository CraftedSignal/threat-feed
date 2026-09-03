---
title: Local Privilege Escalation in util-linux via Race Condition
slug: 2026-09-util-linux-privesc
description: A vulnerability in util-linux allows unprivileged local users to perform arbitrary bind mounts and change file ownership or permissions by exploiting a race condition in SUID mount(8) handling of fstab entries.
date: "2026-09-02T17:16:02Z"
lastmod: "2026-09-03T13:21:23Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:kernel_org:util_linux:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - linux
  - local-exploit
  - kernel
vendors:
  - Kernel.org
products:
  - util-linux
  - util-linux (<= 2.41.5, <= 2.42.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A local unprivileged user who can replace the authorized source or a writable ancestor can redirect SUID mount(8) to bind another host directory.
    confidence_band: high
cves:
  - id: CVE-2026-78410
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78410
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76642
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Monitor for security updates from distribution vendors for util-linux and apply patches immediately.
      owner: IT Operations
      addresses: CVE-2026-78410
      evidence: Source confirms vulnerability in util-linux requiring update.
  gaps:
    - Need to identify all systems with fstab entries containing X-mount options.
updates:
  - at: "2026-09-03T13:21:23Z"
    level: L2
    summary: added coverage for util-linux (<= 2.41.5, <= 2.42.2)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-76642
---

CVE-2026-78410 describes a critical security flaw in the util-linux package, specifically within the handling of restricted bind mounts. The vulnerability stems from the mount(8) command failing to properly pin the source path defined in the fstab file before executing the mount operation. This creates a time-of-check to time-of-use (TOCTOU) race condition. An unprivileged local user who has the ability to manipulate the directory structure or replace the source path can redirect the mount(8) operation to an arbitrary directory on the host. When the fstab entry includes administrative mount options such as X-mount.owner, X-mount.group, or X-mount.mode, the SUID-root mount binary inadvertently applies these permissions changes to the redirected target directory, leading to full privilege escalation. This issue impacts systems where users have permission to trigger mounts defined in fstab.

## Impact

Successful exploitation of this vulnerability allows an unprivileged local attacker to elevate their privileges to root by changing the ownership or permissions of sensitive files or directories on the system. This can lead to total system compromise, unauthorized data access, and persistence. The vulnerability affects all systems utilizing the vulnerable version of the util-linux package, particularly those configured with user-accessible mount points in fstab.

## Recommendation

Prioritize patching the util-linux package across all Linux distributions as soon as security updates are provided by upstream maintainers or OS vendors. Monitor for unauthorized usage of mount(8) by non-root users in local environments, specifically looking for process executions involving fstab-defined mount points and the use of user-controlled mount options.
