---
title: Electron Use-After-Free Vulnerability in PowerMonitor Module
slug: 2024-01-29-electron-use-after-free
description: A use-after-free vulnerability exists in the `powerMonitor` module of Electron applications on Windows and macOS. When the native `PowerMonitor` object is garbage-collected, dangling references are retained by OS-level resources. Subsequent session-change events on Windows or system shutdowns on macOS may dereference freed memory, potentially leading to a crash or memory corruption.
date: "2026-04-03T02:39:52Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - electron
  - use-after-free
  - vulnerability
  - powermonitor
  - windows
  - macos
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-jjp3-mq3x-295m
iocs:
  - type: email
    value: security@electronjs.org
ioc_counts:
  email: 1
rules:
  - title: Electron PowerMonitor Use-After-Free - Process Crash
    description: Detects process crashes in Electron applications that may be related to the PowerMonitor use-after-free vulnerability.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1068
    data_sources:
      - application
      - windows
  - title: Electron PowerMonitor Use-After-Free - Unexpected Shutdown (macOS)
    description: Detects unexpected system shutdowns or restarts on macOS where Electron applications utilizing powerMonitor are present.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1068
    data_sources:
      - system
      - macos
rules_count: 2
---

A use-after-free vulnerability has been identified in the `powerMonitor` module of Electron versions prior to 38.8.6, between 39.0.0-alpha.1 and 39.8.1, between 40.0.0-alpha.1 and 40.8.0, and between 41.0.0-alpha.1 and 41.0.0-beta.8. This vulnerability occurs when the native `PowerMonitor` object is garbage-collected, but associated OS-level resources (message window on Windows, shutdown handler on macOS) retain dangling references. This issue can lead to a crash or memory corruption when a session-change event on Windows or system shutdown on macOS attempts to dereference the freed memory. All Electron applications that utilize the `powerMonitor` module and its events (e.g., `suspend`, `resume`, `lock-screen`) are potentially vulnerable. Defenders should prioritize patching Electron to the fixed versions to mitigate the risk.

## Attack Chain

1. An Electron application is built using a vulnerable version of Electron (e.g., 38.8.5).
2. The application utilizes the `powerMonitor` module to listen for system power events.
3. The application runs on a Windows or macOS system.
4. The native `PowerMonitor` object is garbage-collected by the JavaScript engine. The associated OS-level resources on Windows (message window) or macOS (shutdown handler) are not properly released.
5. A session-change event occurs on Windows (e.g., user lock/unlock) or a system shutdown is initiated on macOS.
6. The OS attempts to notify the previously freed `PowerMonitor` object about the session change or shutdown event.
7. The OS dereferences the dangling pointer, leading to a use-after-free condition.
8. The application crashes or experiences memory corruption, potentially leading to denial of service or other undefined behavior.

## Impact

Successful exploitation of this use-after-free vulnerability can lead to application crashes and potential memory corruption. The impact affects any Electron application that uses the `powerMonitor` module, potentially disrupting application functionality and causing data loss. The vulnerability affects all platforms where Electron applications are deployed, specifically Windows and macOS. The severity is high due to the potential for application instability and the lack of application-side workarounds, requiring a patch to the Electron framework itself.

## Recommendation

*   Upgrade Electron to a patched version (41.0.0-beta.8, 40.8.0, 39.8.1, or 38.8.6) to resolve the use-after-free vulnerability in the `powerMonitor` module.
*   Monitor application crash logs for indicators of use-after-free conditions, especially following session-change events on Windows or system shutdowns on macOS.
*   Implement application monitoring to detect unexpected memory corruption events, which could be a sign of successful exploitation.
*   Contact security@electronjs.org for any questions or comments about the advisory.
