---
title: Buffer Overflow in U-Boot NFS Handling (CVE-2026-74221)
slug: 2026-09-u-boot-nfs-overflow
description: A buffer overflow in the U-Boot nfs_readlink_reply function allows a malicious NFS server to trigger memory corruption via crafted READLINK replies.
date: "2026-09-29T22:30:06Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:denx_software_engineering:u_boot:*:*:*:*:*:*:*:*
vendors:
  - DENX Software Engineering
products:
  - U-Boot (< 2026.10-rc5)
cves:
  - id: CVE-2026-74221
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-74221
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Embedded Systems Security
  mitigation_plan:
    - priority: immediate
      action: Upgrade U-Boot to version 2026.10-rc5 or later.
      owner: IT Operations
      addresses: CVE-2026-74221
      evidence: Source explicitly identifies vulnerability in versions before 2026.10-rc5.
---

U-Boot versions prior to 2026.10-rc5 are vulnerable to a buffer overflow flaw in the nfs_readlink_reply() function located within net/nfs-common.c. This vulnerability is triggered when the bootloader processes responses from an NFS server during the network boot process. By providing a specially crafted NFS READLINK reply containing negative or oversized symlink length values, an attacker-controlled or compromised NFS server can cause memory corruption within the bootloader's execution environment. Successful exploitation may lead to a crash of the U-Boot process or potentially arbitrary code execution at the bootloader level. This is particularly relevant for embedded devices and systems that rely on network-based booting for deployment and maintenance.

## Impact

The vulnerability poses a significant risk to systems that perform network booting from untrusted or unauthenticated NFS sources. An attacker capable of positioning themselves as an NFS server can compromise the integrity of the device during its initial boot stage, potentially bypassing secure boot mechanisms or installing persistent malicious payloads before the operating system even loads. This can impact a wide array of IoT, industrial, and networking hardware that utilizes the U-Boot bootloader.

## Recommendation

Update all U-Boot instances to version 2026.10-rc5 or later to address the vulnerable code in net/nfs-common.c. In environments where immediate patching is not possible, implement strict network segmentation to ensure the NFS boot server is isolated from untrusted traffic and restrict access to the NFS mount point to authorized, hardened infrastructure only.
