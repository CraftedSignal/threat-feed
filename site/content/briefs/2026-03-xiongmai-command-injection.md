---
title: Xiongmai DVR/NVR Root OS Command Injection Vulnerability (CVE-2026-34005)
slug: 2026-03-xiongmai-command-injection
description: Xiongmai DVR/NVR devices are vulnerable to root OS command injection (CVE-2026-34005) due to shell metacharacters in the HostName value, exploitable via an authenticated DVRIP request, potentially allowing arbitrary command execution with root privileges.
date: "2026-03-29T17:16:44Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - CVE-2026-34005
  - command-injection
  - xiongmai
  - dvr
  - nvr
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34005
  - https://uky007.github.io/CVE-2026-34005/
  - https://www.xiongmaitech.com
rules:
  - title: Detect DVRIP NetWork.NetCommon HostName Manipulation
    description: Detects network connections to port 34567, potentially indicating attempts to exploit CVE-2026-34005 by manipulating the HostName value in the NetWork.NetCommon configuration handler.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1550.002
    data_sources:
      - network_connection
      - windows
  - title: Detect DVRIP Traffic on Non-Standard Ports
    description: Detects DVRIP protocol (typically TCP port 34567) being used on non-standard ports, which could indicate malicious activity or port redirection.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Xiongmai DVR/NVR devices, specifically models AHB7008T-MH-V2 and NBD7024H-P running firmware version 4.03.R11, are susceptible to root OS command injection (CVE-2026-34005). This vulnerability arises from the inadequate sanitization of the HostName value within the NetWork.NetCommon configuration handler. An authenticated attacker can inject shell metacharacters into the HostName parameter through a DVRIP protocol request via TCP port 34567. Due to the use of the `system()` function, these…
