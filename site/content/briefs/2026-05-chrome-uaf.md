---
title: CVE-2026-7925 Use-After-Free Vulnerability in Chromium Chromoting
slug: 2026-05-chrome-uaf
description: CVE-2026-7925 is a use-after-free vulnerability in the Chromoting component of Google Chrome, also affecting Microsoft Edge.
date: "2026-05-07T14:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*
tags:
  - use-after-free
  - vulnerability
  - chromoting
vendors:
  - Google
  - Microsoft
products:
  - Chrome
  - Edge
cves:
  - id: CVE-2026-7925
    cvss: 7.8
    epss: 5e-05
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-7925
  - https://chromereleases.googleblog.com/2026
rules:
  - title: Detect CVE-2026-7925 Exploitation Attempt - Unusual Chrome Child Process
    description: Detects CVE-2026-7925 exploitation — Monitors for unusual child processes spawned by Chrome, which could indicate code execution following a use-after-free.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1566
    data_sources:
      - process_creation
      - windows
  - title: Detect CVE-2026-7925 Exploitation Attempt - Unusual Edge Child Process
    description: Detects CVE-2026-7925 exploitation — Monitors for unusual child processes spawned by Edge, which could indicate code execution following a use-after-free.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1566
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-7925 is a use-after-free vulnerability identified within the Chromoting component of the Chromium project, impacting both Google Chrome and Microsoft Edge. A use-after-free vulnerability occurs when an application attempts to use memory after it has been freed, which can lead to crashes, arbitrary code execution, or other exploitable behaviors. Microsoft Edge, which is built upon the Chromium codebase, inherits this vulnerability. Defenders should monitor for unusual process behavior and promptly apply updates provided by Google and Microsoft.

## Attack Chain

1. An attacker crafts a malicious Chromoting session request.
2. The Chromoting component processes the crafted request.
3. The vulnerable code path in Chromoting is triggered.
4. Memory is freed within the Chromoting component.
5. The code attempts to access the freed memory location.
6. A use-after-free condition occurs, potentially leading to a crash.
7. With further exploitation, the attacker could potentially achieve arbitrary code execution.
8. The attacker gains control of the affected process, potentially escalating privileges and compromising the system.

## Impact

A successful exploitation of CVE-2026-7925 could allow an attacker to execute arbitrary code within the context of the affected browser (Chrome or Edge). This could lead to information disclosure, system compromise, or other malicious activities. While the number of potential victims and specific sectors targeted are unknown, the widespread use of Chrome and Edge means a large user base is potentially at risk.

## Recommendation

*   Apply the latest security updates for Google Chrome to remediate CVE-2026-7925.
*   Apply the latest security updates for Microsoft Edge (Chromium-based) to remediate CVE-2026-7925.
*   Monitor process creation events for unusual or suspicious activity originating from Chrome or Edge processes, which may indicate exploitation attempts (see Sigma rules below).
