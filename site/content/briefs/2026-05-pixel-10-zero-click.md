---
title: Pixel 10 Zero-Click Exploit Chain via Dolby and VPU Driver Vulnerabilities
slug: 2026-05-pixel-10-zero-click
description: A zero-click exploit chain was developed for the Google Pixel 10, achieving root access on Android by exploiting a patched Dolby vulnerability (CVE-2025-54957) and a memory mapping vulnerability in the Chips&Media Wave677DV video processing unit (VPU) driver.
date: "2026-05-13T17:21:02Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - android
  - zero-click
  - privilege-escalation
  - kernel-exploit
vendors:
  - Google
  - Chips&Media
products:
  - Pixel 10
  - Tensor G5 chip
  - Wave677DV
affected_os:
  - Android
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2025-54957
    cvss: 9.8
    epss: 0.00027
references:
  - https://projectzero.google/2026/05/pixel-10-exploit.html
  - https://projectzero.google/2026/01/pixel-0-click-part-1.html
  - https://project-zero.issues.chromium.org/428075495#attachment76717436
  - https://www.chipsnmedia.com/en/products/video.php
  - https://www.smartprix.com/bytes/google-tensor-g5-on-pixel-10-series-what-we-know-so-far/
  - https://project-zero.issues.chromium.org/issues/463438263
  - https://projectzero.google/2025/11/defeating-kaslr-by-doing-nothing-at-all.html
rules:
  - title: Detect VPU Driver Access via Process Creation
    description: Detects process creation events where a process interacts with the /dev/vpu device, potentially indicating exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect Large Memory Mapping of VPU Device
    description: Detects suspicious memory mapping sizes when interacting with the /dev/vpu device, indicating potential exploitation of the mmap vulnerability.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect Overwrite of Kernel Functions via Mmap
    description: Detects attempts to overwrite kernel functions after memory mapping the VPU device, indicative of privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
rules_count: 3
---

Project Zero researchers developed a zero-click exploit chain for the Google Pixel 10, building upon their previous work on the Pixel 9. The exploit chain leverages two key vulnerabilities: an updated exploit for CVE-2025-54957 (a Dolby vulnerability patched in January 2026) and a newly discovered memory mapping vulnerability in the Chips&Media Wave677DV video processing unit (VPU) driver found at /dev/vpu on the Tensor G5 chip. The VPU driver vulnerability allows for arbitrary read/write access to the kernel, leading to complete device compromise. This research highlights the critical need for robust security practices in Android driver development and the importance of rapid patching for newly discovered vulnerabilities. The updated Dolby UDC exploit is effective only on unpatched devices with a security patch level of December 2025 or earlier.

## Attack Chain

1. The attacker sends a crafted media file to the target device, leveraging the Dolby vulnerability (CVE-2025-54957).
2. The crafted media file triggers a vulnerability in the Dolby decoder, allowing code execution in the context of the media process.
3. The exploit overwrites `dap_cpdp_init` in the Dolby library to redirect control flow.
4. The attacker gains initial code execution, but limited privileges.
5. The attacker interacts with the `/dev/vpu` device driver for the Chips&Media Wave677DV VPU.
6. The attacker exploits the `vpu_mmap` function to map the VPU's MMIO register region into userland, specifying a size larger than the register region.
7. This allows the attacker to map arbitrary physical memory, including the kernel image, into userland.
8. The attacker overwrites kernel functions with malicious code, gaining kernel code execution and root privileges.

## Impact

Successful exploitation of this chain grants the attacker complete control over the targeted Google Pixel 10 device. This includes the ability to access sensitive user data, install malicious applications, and perform any action with root privileges. Given the zero-click nature of the initial vulnerability, a large number of devices could be compromised without user interaction. The affected sector is mobile devices.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect potential exploitation attempts targeting the VPU driver.
*   Monitor for unexpected memory mappings involving the `/dev/vpu` device, as indicated by the successful exploitation in the Attack Chain (log source: process_creation).
*   While CVE-2025-54957 is patched, monitor for older devices potentially vulnerable to the Dolby exploit, as described in the Overview.
*   Review kernel driver code, particularly memory mapping functions, for similar vulnerabilities as described in "The Holy Grail of Kernel Vulnerabilities" to prevent future exploits.
