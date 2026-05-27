---
title: Realtek rtl819x Local Privilege Escalation Vulnerability
slug: 2026-05-realtek-lpe
description: A local privilege escalation vulnerability exists in Realtek rtl819x Jungle SDK due to missing capability checks on ioctl commands, allowing unprivileged users to gain root privileges on affected Linux systems.
date: "2026-05-27T12:51:08Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - realtek
  - linux
vendors:
  - Realtek
  - Qualcomm
products:
  - rtl819x Jungle SDK
  - rtl8192c
  - rtl8192d
  - rtl8192e
  - rtl8188e
  - rtl8812
  - rtl8881a
  - rtl8197f
affected_os:
  - Linux 3.18.48
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-36355
    cvss: 7.7
    epss: 6e-05
references:
  - https://www.exploit-db.com/exploits/52580
  - http://www.realtek.com
  - https://github.com/iptime-gpl/userapps_n104qi
  - CVE-2026-36355
rules:
  - title: Detect Realtek KPwn Exploit Execution
    description: Detects execution of the Realtek KPwn local privilege escalation exploit based on process name.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect Realtek KPwn Exploit - IOCTL Calls
    description: Detects potential Realtek KPwn exploit attempts based on ioctl calls related to memory read/write primitives.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A local privilege escalation vulnerability (CVE-2026-36355) has been identified in the Realtek rtl819x Jungle SDK, affecting devices using the out-of-tree WiFi driver SDK. The vulnerability stems from missing capability checks on ioctl commands 0x89F5 (write_mem) and 0x89F6 (read_mem), allowing any unprivileged user to read and write kernel memory. An exploit (EDB-52580) has been published, demonstrating successful privilege escalation on Linux 3.18.48, ARMv7 Cortex-A7, Qualcomm MDM9607, and rtl8192es.ko. This vulnerability affects a wide range of Realtek chips, including RTL8192C/D/E, RTL8188E, RTL8812, RTL8881A, and RTL8197F. The availability of a working exploit significantly increases the risk to vulnerable systems.

## Attack Chain

1.  An unprivileged user executes the kpwn exploit binary.
2.  The exploit identifies a vulnerable Realtek rtl819x wireless interface.
3.  The exploit scans kernel memory to locate the `init_task` structure.
4.  The exploit auto-detects the offsets for `tasks`, `pid`, `cred`, and `comm` within the `task_struct`.
5.  The exploit walks the task list to find the current process's `task_struct` using its PID.
6.  The exploit reads the current user's credentials from the kernel memory.
7.  The exploit overwrites the user's credentials in kernel memory, setting UID and GID to 0.
8.  The user's privileges are escalated to root, granting full system access.

## Impact

Successful exploitation of this vulnerability allows an unprivileged local user to gain full root privileges on the affected system. This can lead to complete system compromise, including data theft, modification, and destruction, as well as the installation of malware and backdoors. The wide range of affected Realtek chips means numerous embedded devices and IoT devices are potentially vulnerable.

## Recommendation

*   Apply available patches or mitigations from Realtek to address CVE-2026-36355 on affected rtl819x based devices.
*   Monitor for the execution of the `kpwn` exploit binary on Linux systems using process creation logs, and deploy the Sigma rule "Detect Realtek KPwn Exploit Execution" to your SIEM.
*   Implement strict access controls and limit access to wireless interfaces to authorized users only.
*   Enable logging for ioctl calls on Realtek wireless interfaces to detect attempts to use IOCTL_WRITE (0x89F5) and IOCTL_READ (0x89F6) with unexpected parameters.
