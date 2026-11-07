---
brief_id: brief-2026-11-07-linux-wacom-hid-oob
event_id: brief-2026-11-07-linux-wacom-hid-oob
revision: 1
activity_at: "2026-11-07T06:21:59Z"
title: 'Linux Kernel: Wacom HID driver out-of-bounds heap read (CVE-2026-98499)'
slug: 2026-11-linux-wacom-hid-oob
description: A kernel heap out-of-bounds read vulnerability in the Linux wacom HID driver allows unprivileged users with access to /dev/uhid to leak KASLR slide and kernel heap addresses via maliciously crafted HID descriptors.
date: "2026-11-07T06:21:59Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*
products:
  - Linux Kernel (< 6.12.58)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The flaw allows an unprivileged user with write access to /dev/uhid to trigger an OOB read by providing a maliciously crafted HID descriptor.
    confidence_band: high
cves:
  - id: CVE-2026-98499
    cvss: 8.1
    epss: 0.0039
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=7E89FFB9-A75E-527A-9FFB-041E725440BA
  - https://nvd.nist.gov/vuln/detail/CVE-2026-98499
  - https://sploitus.com/exploit?id=7E89FFB9-A75E-527A-9FFB-041E725440BA&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Linux kernel to the identified fixed versions.
      owner: IT Operations
      due: 48h
      evidence: Upstream commit 9aa237cf6649
  hunt_leads:
    - lead: Monitor for suspicious use of /dev/uhid by non-authorized users or services
      technique_id: T1068
      data_needed:
        - Auditd/syslog for open() or write() calls to /dev/uhid
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The PoC requires /dev/uhid write access to trigger the vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Restrict permissions on /dev/uhid to authorized system users only.
      owner: IT Operations
      addresses: CVE-2026-98499
      evidence: 'Runtime requirement 1: /dev/uhid is writable by the calling uid.'
---

CVE-2026-98499 is a kernel heap out-of-bounds (OOB) read vulnerability located in `wacom_wac_pen_serial_enforce()`. The flaw occurs when the driver processes HID descriptors with specific usage configurations, allowing an attacker to walk past the received report buffer. Exploitation results in the extraction of kernel memory values, which are delivered to userspace as `MSC_SERIAL` input events. A public proof-of-concept exists that demonstrates the information leak of KASLR slide and `uhid_device` heap base on Linux kernels through version 6.12.58.

## Attack Chain
1. Attacker ensures the process has write permissions to `/dev/uhid` (e.g., membership in `uhid` group).
2. Attacker initializes a virtual HID device via `uhid`.
3. Attacker submits a maliciously crafted HID descriptor containing `HID_DG_PEN`, `HID_DG_STYLUS`, and `HID_DG_TOOLSERIALNUMBER` usages.
4. Attacker uses 2-byte usage items (`0x1A`/`0x2A`) to avoid truncation and trigger the OOB read loop.
5. The wacom driver binds to the virtual device and processes the descriptor.
6. The `wacom_wac_pen_serial_enforce()` function accesses memory out-of-bounds due to an improper loop limit based on `field->maxusage`.
7. Leaked kernel memory values are written to `MSC_SERIAL` and reported to `/dev/input/eventN`.
8. Attacker reads the `MSC_SERIAL` event from the input node to recover kernel pointers.

## Impact
Successful exploitation allows an unprivileged local user to bypass KASLR and leak sensitive kernel heap pointers. While the current PoC lacks a write primitive, these leaks are critical prerequisites for more complex kernel exploitation chains.

## Recommendation
- Patch the kernel immediately using upstream commit `9aa237cf6649` or stable branch fix `eaa7d29341ef`.
- Audit system configurations for access to `/dev/uhid`. Restrict write access to this device node to only necessary and trusted service accounts to prevent local users from creating virtual HID devices.
- Implement monitoring for processes that interact with `/dev/uhid` and subsequently monitor `/dev/input/event*` nodes if those processes are not trusted HID services.
