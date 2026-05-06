---
title: Electron Use-After-Free Vulnerability in Offscreen Rendering with Child Windows
slug: 2026-04-electron-use-after-free
description: A use-after-free vulnerability (CVE-2026-34774) exists in Electron applications using offscreen rendering and allowing child windows, potentially leading to crashes or memory corruption if the parent WebContents is destroyed before the child window.
date: "2026-04-03T02:42:27Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - electron
  - use-after-free
  - vulnerability
  - cve-2026-34774
references:
  - https://github.com/advisories/GHSA-532v-xpq5-8h95
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

Electron applications utilizing offscreen rendering (`webPreferences.offscreen: true`) and permitting child windows via `window.open()` are susceptible to a use-after-free vulnerability, identified as CVE-2026-34774. This vulnerability arises when a parent offscreen `WebContents` is destroyed while a child window remains open. Subsequently, paint frames on the child window dereference freed memory, which can result in application crashes or memory corruption. Applications are only affected if they meet both criteria: employing offscreen rendering and allowing child window creation. Electron versions prior to 39.8.1, versions between 40.0.0-alpha.1 and 40.7.0, and versions between 41.0.0-alpha.1 and 41.0.0 are vulnerable. Defenders should prioritize patching or implementing workarounds to mitigate the risk of exploitation.

## Attack Chain

1. An Electron application is launched with `webPreferences.offscreen` set to `true`, enabling offscreen rendering.
2. The application's `setWindowOpenHandler` is configured to permit the creation of child windows using `window.open()`.
3. User interaction or application logic triggers the creation of a child window.
4. The parent offscreen `WebContents` is destroyed, for example, by closing the main window or navigating to a different page that releases the `WebContents` object.
5. The child window remains open and continues to receive paint events.
6. During a paint event, the child window attempts to access memory that was previously allocated to the parent `WebContents` but has now been freed.
7. This memory access results in a use-after-free condition, leading to a crash or memory corruption.
8. An attacker can potentially leverage this memory corruption to execute arbitrary code within the context of the Electron application.

## Impact

Successful exploitation of this vulnerability can lead to application crashes and potential arbitrary code execution. The severity is high, as code execution could allow an attacker to gain control of the affected application, potentially leading to data theft, system compromise, or other malicious activities. Organizations using vulnerable Electron applications may experience service disruptions and potential data breaches. The number of affected applications and users is potentially large, given the widespread use of Electron for cross-platform desktop application development.

## Recommendation

*   Upgrade to Electron versions 39.8.1, 40.7.0, or 41.0.0 or later to address CVE-2026-34774.
*   Implement the suggested workarounds by either denying child window creation from offscreen renderers in your `setWindowOpenHandler` or ensuring child windows are closed before the parent is destroyed.
*   Monitor application logs for unexpected crashes or memory-related errors that may indicate exploitation attempts.
*   Consider implementing runtime application self-protection (RASP) techniques to detect and prevent use-after-free vulnerabilities.
