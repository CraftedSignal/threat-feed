---
title: Electron Use-After-Free Vulnerability in PowerMonitor Module
slug: 2024-01-29-electron-use-after-free
description: A use-after-free vulnerability exists in the `powerMonitor` module of Electron applications on Windows and macOS. When the native `PowerMonitor` object is garbage-collected, dangling references are retained by OS-level resources. Subsequent session-change events on Windows or system shutdowns on macOS may dereference freed memory, potentially leading to a crash or memory corruption.
date: "2026-04-03T02:39:52Z"
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

A use-after-free vulnerability has been identified in the `powerMonitor` module of Electron versions prior to 38.8.6, between 39.0.0-alpha.1 and 39.8.1, between 40.0.0-alpha.1 and 40.8.0, and between 41.0.0-alpha.1 and 41.0.0-beta.8. This vulnerability occurs when the native `PowerMonitor` object is garbage-collected, but associated OS-level resources (message window on Windows, shutdown handler on macOS) retain dangling references. This issue can lead to a crash or memory corruption when a…
