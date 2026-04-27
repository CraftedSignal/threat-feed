---
title: Electron Use-After-Free Vulnerability in Offscreen Rendering with Child Windows
slug: 2026-04-electron-use-after-free
description: A use-after-free vulnerability (CVE-2026-34774) exists in Electron applications using offscreen rendering and allowing child windows, potentially leading to crashes or memory corruption if the parent WebContents is destroyed before the child window.
date: "2026-04-03T02:42:27Z"
severities:
  - high
tags:
  - electron
  - use-after-free
  - vulnerability
  - cve-2026-34774
references:
  - https://github.com/advisories/GHSA-532v-xpq5-8h95
ioc_counts:
  email: 1
rules:
  - title: Detect Electron App with Offscreen Rendering Enabled
    description: Detects Electron applications launched with the --enable-features=OffscreenRendering flag, which indicates offscreen rendering is enabled and the application may be vulnerable.
    platform: sigma
    severity: informational
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - process_creation
      - windows
  - title: Detect Electron App Creating Child Windows
    description: Detects Electron applications that may be creating child windows using window.open() API
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Electron applications utilizing offscreen rendering (`webPreferences.offscreen: true`) and permitting child windows via `window.open()` are susceptible to a use-after-free vulnerability, identified as CVE-2026-34774. This vulnerability arises when a parent offscreen `WebContents` is destroyed while a child window remains open. Subsequently, paint frames on the child window dereference freed memory, which can result in application crashes or memory corruption. Applications are only affected if…
