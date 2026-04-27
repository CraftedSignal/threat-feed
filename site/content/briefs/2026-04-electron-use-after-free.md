---
title: Electron Use-After-Free Vulnerability in Offscreen Rendering with Child Windows (CVE-2026-34774)
slug: 2026-04-electron-use-after-free
description: A use-after-free vulnerability exists in Electron versions prior to 39.8.1, 40.7.0, and 41.0.0 affecting applications using offscreen rendering and allowing child windows, leading to potential crashes or memory corruption.
date: "2026-04-04T00:16:18Z"
severities:
  - high
tags:
  - electron
  - use-after-free
  - vulnerability
  - CVE-2026-34774
  - offscreen-rendering
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34774
rules:
  - title: Electron Child Window Memory Access
    description: Detects potential use-after-free exploitation attempts related to Electron child windows accessing memory after the parent has been destroyed.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1070.001
    data_sources:
      - process_creation
      - windows
  - title: Electron Offscreen Rendering Detection
    description: Detects Electron applications running with offscreen rendering enabled, potentially vulnerable to CVE-2026-34774.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Electron is a framework used to build cross-platform desktop applications with JavaScript, HTML, and CSS. A use-after-free vulnerability, identified as CVE-2026-34774, affects Electron applications utilizing offscreen rendering (webPreferences.offscreen: true) and permitting child windows through `window.open()`. This vulnerability resides in versions prior to 39.8.1, 40.7.0, and 41.0.0. Exploitation occurs when the parent offscreen WebContents object is destroyed while a child window remains…
