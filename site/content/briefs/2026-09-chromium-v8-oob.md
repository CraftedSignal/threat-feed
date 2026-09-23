---
title: Chromium V8 Engine Out-of-Bounds Memory Access Vulnerability
slug: 2026-09-chromium-v8-oob
description: CVE-2026-0899 is an out-of-bounds memory access vulnerability in the Chromium V8 JavaScript engine that may result in memory corruption, process crashes, or arbitrary code execution.
date: "2026-09-18T07:20:15Z"
lastmod: "2026-09-23T14:04:20Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:google:chromium:*:*:*:*:*:*:*:*
  - cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - chromium
  - browser-security
vendors:
  - Google
products:
  - Chromium (< 144.0.7559.59)
  - Chromium (< 153.0.8010.36)
cves:
  - id: CVE-2026-0899
    cvss: 8.8
    epss: 0.00419
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-0899
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-87536
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Update Chromium to 144.0.7559.59 or later
      owner: IT Operations
      addresses: CVE-2026-0899
      evidence: CVE-2026-0899 vulnerability in V8 engine
updates:
  - at: "2026-09-23T14:04:20Z"
    level: L2
    summary: added coverage for Chromium (< 153.0.8010.36)
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-87536
---

CVE-2026-0899 represents a security vulnerability identified within the V8 JavaScript engine, which serves as the core execution environment for Chromium-based web browsers. This vulnerability is classified as an out-of-bounds (OOB) memory access issue. Such flaws typically arise when the engine fails to properly validate the bounds of an array or memory buffer during JIT (Just-In-Time) compilation or execution of JavaScript code. If successfully exploited by an attacker via a maliciously crafted webpage, this vulnerability could allow for heap-based memory corruption. Potential consequences of this memory corruption include the application crashing, which leads to a denial of service, or the attainment of arbitrary code execution within the security context of the browser process. As Chromium serves as the foundation for Google Chrome, Microsoft Edge, and many other browser platforms, this vulnerability affects a wide range of browser users across Windows, Linux, and macOS environments.

## Impact

Successful exploitation of CVE-2026-0899 could allow an attacker to bypass browser security sandboxes, leading to arbitrary code execution on the underlying host system. This poses a significant risk to all users of Chromium-based browsers, potentially facilitating data theft, installation of persistent malware, or credential harvesting.

## Recommendation

Prioritized, concrete actions for detection engineering teams:
* Monitor for browser process instability, which may indicate active attempts to trigger the memory corruption vulnerability.
* Ensure all browser endpoints are updated to the latest stable channel version provided by the respective vendor, as patches for Chromium vulnerabilities are typically distributed via browser-level update mechanisms.
* Verify that automated patch management processes are configured to update Chromium-based browsers (such as Chrome and Edge) within the standard 24-48 hour vulnerability response window.
