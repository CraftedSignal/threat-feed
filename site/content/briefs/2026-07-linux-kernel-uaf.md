---
title: Public Exploit for Linux Kernel Use-After-Free Vulnerability CVE-2026-43499
slug: 2026-07-linux-kernel-uaf
description: A public exploit has been published for CVE-2026-43499, a Use-After-Free vulnerability in the Linux Kernel, demonstrated to achieve KASLR bypass and potential privilege escalation on Android 15 devices running Linux Kernel 5.15.149, significantly elevating risk for unpatched systems.
date: "2026-07-13T08:01:56Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*
tags:
  - linux
  - kernel
  - vulnerability
  - use-after-free
  - privilege-escalation
  - android
vendors:
  - Linux Foundation
  - OPPO
products:
  - Linux Kernel 5.15.149
  - OPPO Find X6 Pro (PGEM10)
affected_os:
  - Android 15 (ColorOS 15.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Exploit for Use After Free in Linux Linux_Kernel CVE-2026-43499... This project focuses on adapting the CVE-2026-43499 (GhostLock) vulnerability... to achieve Perf KASLR bypass
    confidence_band: high
cves:
  - id: CVE-2026-43499
    cvss: 7.8
    epss: 0.00125
references:
  - https://sploitus.com/exploit?id=529FD1C2-FD47-576F-AE7C-1F592B7CB594
  - https://github.com/NebuSec/CyberMeowfia
  - https://github.com/pubglite55/oppo-ghostlock
  - https://nebusec.ai/research/ionstack-part-2/
  - https://github.com/oppo-source/android_kernel_oppo_sm8550
  - https://github.com/oppo-source/android_kernel_common_oppo_sm8550
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=529FD1C2-FD47-576F-AE7C-1F592B7CB594
  - type: url
    value: https://github.com/NebuSec/CyberMeowfia
  - type: url
    value: https://github.com/pubglite55/oppo-ghostlock
  - type: url
    value: https://nebusec.ai/research/ionstack-part-2/
  - type: url
    value: https://github.com/oppo-source/android_kernel_oppo_sm8550
  - type: url
    value: https://github.com/oppo-source/android_kernel_common_oppo_sm8550
ioc_counts:
  url: 6
---

A public exploit has been made available on Sploitus for CVE-2026-43499, a critical Use-After-Free vulnerability in the Linux Kernel. This exploit, codenamed "GhostLock," has been specifically adapted and demonstrated on the OPPO Find X6 Pro (PGEM10) device, which runs Android 15 (ColorOS 15.0) on Linux Kernel 5.15.149-android13. The adaptation includes a successful Kernel Address Space Layout Randomization (KASLR) bypass, achieved through the use of `perf_event_open` with `callchain sampling`. The existence of a readily available and working exploit significantly increases the risk for organizations and individuals operating unpatched Linux systems, particularly those with similar kernel versions or Android devices, enabling attackers to achieve local privilege escalation to kernel level.

## Attack Chain

1. An attacker identifies a target system running a vulnerable Linux Kernel version, such as 5.15.149-android13, which is susceptible to the CVE-2026-43499 Use-After-Free flaw.
2. To circumvent Kernel Address Space Layout Randomization (KASLR), the attacker leverages kernel mechanisms, specifically `perf_event_open` combined with `callchain sampling`, to leak kernel memory addresses.
3. The attacker analyzes the obtained call chain data, including maximum single frame depth (e.g., 0x1F0), to accurately determine the randomized base address of the kernel or critical kernel objects.
4. A malicious sequence of operations or specific kernel calls is crafted to trigger the Use-After-Free condition inherent in CVE-2026-43499. This involves deallocating a kernel memory region and then re-using it for controlled malicious purposes.
5. By manipulating the freed and subsequently reallocated memory, the attacker corrupts essential kernel data structures, such as process credentials, task control blocks, or function pointers.
6. The memory corruption enables the attacker to execute arbitrary code within kernel mode or modify their process's privileges to gain full root access on the compromised system.
7. With kernel-level control, the attacker can proceed with post-exploitation activities, including installing persistent backdoors, exfiltrating sensitive data, or further compromising the system's integrity.

## Impact

Successful exploitation of CVE-2026-43499 grants an attacker full root privileges on the affected Linux system, leading to complete system compromise. This allows for arbitrary code execution in kernel mode, enabling the attacker to bypass all security controls, access or modify any data, install malware, or establish persistence. The presence of a public exploit targeting specific Android devices (OPPO Find X6 Pro) indicates a clear path for attackers to compromise mobile devices running affected kernel versions. The impact extends to data breaches, unauthorized access, and potential denial of service, with severe consequences for data confidentiality, integrity, and availability.

## Recommendation

* Patch CVE-2026-43499 immediately on all affected Linux Kernel systems and Android devices to prevent exploitation of the Use-After-Free vulnerability.
* Monitor for unusual or excessive usage of `perf_event_open` on Linux systems, particularly if originating from unprivileged processes, as this is used in the KASLR bypass technique described.
* Review kernel source code updates for Linux Kernel 5.15.149-android13 and subsequent versions to ensure the `GhostLock` vulnerability is addressed.
* Block access to the exploit sources listed in the IOC table at the network perimeter or endpoint detection solutions to prevent download and execution.
