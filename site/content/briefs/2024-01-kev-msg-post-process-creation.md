---
title: macOS Kernel-to-Userland Process Creation Notification via undocumented kev_msg_post
slug: 2024-01-kev-msg-post-process-creation
description: The kev_msg_post function can be abused by malware to broadcast process creation notifications from a kernel extension (kext) to a user-mode application, potentially bypassing security tools that rely on standard APIs and leading to undetected malicious activity.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - kernel-extension
  - kev_msg_post
  - macos
  - process-monitoring
vendors:
  - Apple
  - Objective-See
products:
  - BlockBlock
affected_os:
  - macOS
references:
  - https://objective-see.org/blog/blog_0x0B.html
rules:
  - title: Detect Userland Process Requesting Kernel Event Vendor Code
    description: Detects userland processes using ioctl to get the kernel event vendor code, which is a prerequisite to receiving process notifications from a kext.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1016
    data_sources:
      - process_creation
      - macos
  - title: Detect Userland Process Setting Kernel Event Filters
    description: Detects userland processes using ioctl to set kernel event filters, indicating an attempt to subscribe to kernel events.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1016
    data_sources:
      - process_creation
      - macos
rules_count: 2
---

This threat brief describes the abuse of the undocumented `kev_msg_post` function in macOS to broadcast process creation notifications from a kernel extension (kext) to a user-mode application. This technique, highlighted in Objective-See's research, allows a kext to bypass standard userland APIs for process monitoring. The `kev_msg_post` function is part of the Kernel Events API. It's designed for kernel-to-userland communication but lacks proper documentation, which makes it difficult to monitor.

The communication involves a kext utilizing `kev_msg_post` to send data to a user-mode application through a system socket.  Objective-See's BlockBlock tool uses this technique to correlate persistent file I/O events with the responsible process.  Abuse of `kev_msg_post` can allow malicious kexts to exfiltrate sensitive kernel-level information or trigger actions in user-mode without detection by conventional monitoring tools. This technique is relevant to defenders because it provides a stealthy mechanism for malware to operate within macOS, potentially leading to undetected data theft, privilege escalation, or system compromise.

## Attack Chain

1.  A malicious kext is loaded into the macOS kernel, often requiring elevated privileges or exploiting a vulnerability.
2.  The kext uses the `kev_vendor_code_find` function to obtain a vendor ID associated with the kext (e.g., "com.objective-see").
3.  The kext registers for process execution events using kauth or MAC policies.
4.  When a new process is created, the kext's callback function is triggered.
5.  The kext populates a `kev_msg` structure with process information, including the process ID (PID), user ID (UID), parent process ID (PPID), and path to the executable.
6.  The kext calls the undocumented `kev_msg_post` function to broadcast the process information to a system socket.
7.  A user-mode application with a socket connected to the same vendor ID receives the broadcasted message, extracting the process information.
8.  The attacker can use the process information for malicious purposes, such as injecting code into the new process, monitoring its activity, or terminating it.

## Impact

Successful exploitation could allow attackers to monitor and manipulate processes on a compromised macOS system without detection by standard userland monitoring tools.  This could lead to data exfiltration, privilege escalation, or other malicious activities. Due to the nature of the kernel, even a single successful compromise can lead to complete system compromise.

## Recommendation

*   Monitor for the loading of unsigned or untrusted kernel extensions using system integrity monitoring tools that track kext loading events.
*   Implement detections for user-mode applications creating system sockets with the `SYSPROTO_EVENT` protocol, as described in the "Receiving the Data in User-Mode" section. This can be done using an endpoint detection and response (EDR) solution or auditd.
*   Develop YARA rules to scan kernel memory for the presence of kexts using the undocumented `kev_msg_post` function to detect malicious kexts attempting to communicate outside kernel space.
*   Audit the use of `ioctl` calls with `SIOCGKEVVENDOR` and `SIOCSKEVFILT` to detect user-mode applications attempting to filter for specific kernel events, using the code samples from the "Receiving the Data in User-Mode" section as reference.
