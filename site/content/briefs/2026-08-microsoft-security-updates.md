---
title: Microsoft Security Updates — August 2026
slug: 2026-08-microsoft-security-updates
description: Roundup of five Microsoft security advisories affecting Microsoft Office Excel and Microsoft Edge, with CVSS scores from 7.4 to 8.8.
date: "2026-08-01T01:41:40Z"
lastmod: "2026-08-04T14:29:26Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - roundup
vendors:
  - Microsoft
products:
  - Microsoft Office 2019
  - Microsoft Office LTSC 2021
  - Microsoft Office LTSC 2024
  - Microsoft 365 Apps for Enterprise
  - Microsoft Excel 2016 (< 16.0.5561.1001)
  - Microsoft Edge for Android (< 151.0.4129.59)
  - Microsoft Edge (Chromium-based) (< 151.0.4129.59)
affected_os:
  - Windows
  - Android
cves:
  - id: CVE-2026-62870
    cvss: 8.8
  - id: CVE-2026-65802
    cvss: 7.4
  - id: CVE-2026-66310
    cvss: 7.7
  - id: CVE-2026-66315
    cvss: 7.5
  - id: CVE-2026-66318
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62870
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65802
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66310
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66315
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66318
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62870
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-65802
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-66310
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-66315
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-66318
  - https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security
  - https://docs.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates
updates:
  - at: "2026-08-04T01:42:32Z"
    level: L2
    summary: added CVE-2026-66310
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-66310
  - at: "2026-08-04T01:42:35Z"
    level: L2
    summary: added CVE-2026-66315
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-66315
  - at: "2026-08-04T14:11:28Z"
    level: L2
    summary: added CVE-2026-62870
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-62870
  - at: "2026-08-04T14:11:28Z"
    level: L2
    summary: added CVE-2026-65802
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-65802
  - at: "2026-08-04T14:11:28Z"
    level: L2
    summary: added CVE-2026-66318
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-66318
---

## Overview

This roundup covers five Microsoft security vulnerabilities released in the July 2026 security update cycle and tracked here in August 2026. All are rated **Important** by the Microsoft Security Response Center (MSRC), with CVSS base scores ranging from **7.4 to 8.8**. At the time of release, none of the issues are reported as actively exploited in the wild or publicly disclosed.

The vulnerabilities fall into two product families:

- **Microsoft Office / Excel (1 CVE):** a use-after-free in Excel that can be exploited for remote code execution when a user opens a malicious file.
- **Microsoft Edge (4 CVEs):** two information-disclosure issues in Edge for Android, plus one remote-code-execution and one information-disclosure issue in the Chromium-based Edge desktop/mobile builds.

## Summary

| CVE | CVSS | Product | Impact | Attack vector |
|-----|------|---------|--------|---------------|
| CVE-2026-62870 | 8.8 | Microsoft Office Excel | Remote Code Execution | User opens a specially crafted file |
| CVE-2026-65802 | 7.4 | Microsoft Edge for Android | Information Disclosure | Network-based, user interaction required |
| CVE-2026-66310 | 7.7 | Microsoft Edge for Android | Information Disclosure | Network-based, user interaction required |
| CVE-2026-66315 | 7.5 | Microsoft Edge (Chromium-based) | Remote Code Execution | User visits attacker-controlled webpage |
| CVE-2026-66318 | 8.1 | Microsoft Edge (Chromium-based) | Information Disclosure | User visits attacker-controlled webpage |

## Recommendation

Apply the July 2026 Microsoft security updates for the affected products:

- **Microsoft Edge:** update to version **151.0.4129.59** or later (Chromium base 151.0.7922.71/.72). See the [Edge security release notes](https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security).
- **Microsoft Office / Excel:** install the July 2026 Microsoft 365 Apps security updates. For Excel 2016, apply **KB5002886** / **KB5002877**. See the [Office security updates](https://docs.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates) page for the KB matching your Office installation.

Deploy through Windows Update, Microsoft Update Catalog, WSUS, or your patch-management channel, and verify the product versions listed above are updated.
