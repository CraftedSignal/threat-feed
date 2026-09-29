---
title: Electron Sandbox Restriction Bypass via Popups
slug: 2026-09-electron-sandbox-bypass
description: A vulnerability in Electron prevents popups opened from sandboxed iframes from inheriting security restrictions, allowing potentially malicious content to access the embedding application's full origin.
date: "2026-09-29T22:18:52Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:electronjs:electron:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - sandbox-bypass
  - web-application
vendors:
  - Electron
products:
  - Electron (< 41.10.4, >= 42.0.0-alpha.1 < 42.5.2, >= 43.0.0-alpha.1 < 43.0.0)
cves:
  - id: CVE-2026-102673
    cvss: 8.2
references:
  - https://github.com/advisories/GHSA-hq2x-r82h-9wj4
action_plan:
  priority: elevated
  owners:
    - Software Development
    - Security Engineering
  immediate_actions:
    - action: Upgrade Electron packages to 41.10.4, 42.5.2, or 43.0.0
      owner: Software Development
      due: 72h
      evidence: Fixed Versions section of the advisory
  mitigation_plan:
    - priority: immediate
      action: Implement setWindowOpenHandler to constrain popups from sandboxed frames
      owner: Software Development
      addresses: CVE-2026-102673
      evidence: Workarounds section of the advisory
---

Electron versions prior to 41.10.4, 42.5.2, and 43.0.0 contain a security flaw where popups initiated from a sandboxed iframe via OpenURLFromTab fail to inherit the necessary HTML sandbox attributes. When an application embeds untrusted content within an iframe using the 'allow-scripts' and 'allow-popups' sandbox permissions, a popup window triggered by that content (e.g., via target="_blank" or middle-click) defaults to the host application's full origin. This failure effectively strips the isolation meant to protect the application, granting the untrusted content access to the host's cookies, local storage, and the ability to execute same-origin scripts. This vulnerability poses a significant risk to Electron-based applications that render third-party or untrusted web content in sandboxed environments.

## Impact

Successful exploitation allows untrusted code to break out of its restricted iframe environment and gain the privilege level of the parent application. This can lead to unauthorized data access, such as reading authentication cookies or local storage, and execution of scripts within the application's origin, which may result in data exfiltration or unauthorized actions performed on behalf of the user.

## Recommendation

- Upgrade applications utilizing Electron to version 41.10.4, 42.5.2, 43.0.0, or later to incorporate the patch for CVE-2026-102673.
- Implement a 'setWindowOpenHandler' within the parent 'WebContents' to explicitly deny or constrain popup windows initiated from sandboxed frames.
- Evaluate current iframe implementations and, where possible, remove 'allow-popups' from sandboxed iframes that process untrusted content until the application is upgraded.
