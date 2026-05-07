---
title: macOS Mojave System Lockup via vmmap Utility Targeting PID 1
slug: 2024-01-vmmap-mojave-lockup
description: A bug in macOS Mojave causes a system lockup when the vmmap utility is executed against process ID 1 (launchd), due to a deadlock triggered by XPC calls during symbolication.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - macos
  - lockup
  - vmmap
  - pid1
vendors:
  - Apple
products:
  - macOS Mojave
affected_os:
  - macOS Mojave
references:
  - https://objective-see.org/blog/blog_0x3E.html
rules:
  - title: Detect vmmap Execution Against PID 1
    description: Detects command-line execution of the vmmap utility targeting PID 1, which triggers a system lockup on macOS Mojave.
    platform: sigma
    severity: high
    tactics:
      - impact
    data_sources:
      - process_creation
      - macos
  - title: macOS Mojave System Lockup via vmmap
    description: Detects potential system lockups on macOS Mojave related to vmmap activity by looking for abnormal process termination events following vmmap execution.
    platform: sigma
    severity: medium
    tactics:
      - impact
    data_sources:
      - process_creation
      - macos
rules_count: 2
---

A critical bug exists in macOS Mojave (10.14) where executing the `vmmap` utility against process ID 1, which is always `launchd`, causes a complete system lockup. This issue was discovered when users reported that the TaskExplorer utility, which uses `vmmap` to enumerate loaded dynamic libraries in remote processes, would freeze the system when run. The root cause is that `vmmap` suspends the target process before enumerating memory regions. When `launchd` (PID 1) is targeted, this suspension prevents `vmmap` from completing its symbolication process, which relies on XPC communication facilitated by `launchd`. The blocked XPC call results in a deadlock, requiring a hard reboot of the affected macOS Mojave system.

## Attack Chain

1. An attacker (or a system utility like TaskExplorer) attempts to enumerate loaded libraries of a process.
2. TaskExplorer executes the `vmmap` command, targeting a specific process ID (PID).
3. The `vmmap` utility starts and is given PID 1 as a command-line argument.
4. `vmmap` invokes `task_suspend` to suspend the target process (launchd) before taking a memory snapshot.
5. `vmmap` attempts to symbolicate the memory regions of the suspended process via the CoreSymbolication framework, calling `CoreSymbolication'mmap_storage_daemon`.
6. The CoreSymbolication framework makes XPC calls, including `xpc_connection_resume`, which are routed to launchd.
7. Because launchd is suspended, the XPC requests are never serviced, specifically a call to `libxpc`’s `_xpc_look_up_endpoint` for `com.apple.coresymbolicationd`.
8. This blocked XPC call deadlocks the system, as `vmmap` waits for a response from `launchd`, but `launchd` cannot respond because it is suspended by `vmmap`. The entire system becomes unresponsive, requiring a hard reboot.

## Impact

Successful exploitation of this bug results in a complete system lockup on macOS Mojave. The user loses any unsaved data and must perform a hard reboot to restore functionality. While the bug does not directly lead to data theft or code execution, it causes significant disruption and data loss. This affects any user running macOS Mojave who attempts to run `vmmap` against PID 1, either directly or indirectly through a utility like TaskExplorer.

## Recommendation

*   Deploy the Sigma rule `Detect vmmap Execution Against PID 1` to detect direct attempts to exploit this bug via command-line execution.
*   Investigate any system lockups on macOS Mojave systems and correlate them with `vmmap` executions, using the `macOS Mojave System Lockup via vmmap` rule as a starting point.
*   Consider blocking execution of `vmmap` with PID 1 as an argument via endpoint detection and response (EDR) tools, preventing the vulnerability from being triggered.
