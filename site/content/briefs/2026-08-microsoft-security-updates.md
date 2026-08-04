---
title: Microsoft Security Updates — August 2026
slug: 2026-08-microsoft-security-updates
description: Roundup of five Microsoft security advisories affecting Microsoft Office Excel and Microsoft Edge, with CVSS scores from 7.4 to 8.8.
date: "2026-08-01T01:41:40Z"
lastmod: "2026-08-04T14:37:52Z"
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

This roundup covers 5 Microsoft security vulnerabilities. CVSS base scores range from 7.4 to 8.8. None are reported as actively exploited at the time of release. The issues affect Microsoft Office Excel, Microsoft Edge.

## Summary

| CVE | CVSS | Product | Summary |
|-----|------|---------|---------|
| CVE-2026-62870 | 8.8 | Microsoft Office Excel | Use after free in Microsoft Office Excel allows an unauthorized attacker to execute code over a network. |
| CVE-2026-65802 | 7.4 | Microsoft Edge for Android | External control of file name or path in Microsoft Edge for Android allows an unauthorized attacker to disclose information over a network. |
| CVE-2026-66310 | 7.7 | Microsoft Edge for Android | External control of file name or path in Microsoft Edge for Android allows an unauthorized attacker to disclose information locally. |
| CVE-2026-66315 | 7.5 | Microsoft Edge (Chromium-based) | Use after free in Microsoft Edge (Chromium-based) allows an unauthorized attacker to execute code over a network. |
| CVE-2026-66318 | 8.1 | Microsoft Edge (Chromium-based) | Origin validation error in Microsoft Edge (Chromium-based) allows an unauthorized attacker to disclose information over a network. |

## CVE-2026-62870

Use after free in Microsoft Office Excel allows an unauthorized attacker to execute code over a network.

Affected products:
- Microsoft Office 2019
- Microsoft Office LTSC 2021
- Microsoft Office LTSC 2024
- Microsoft 365 Apps for Enterprise
- Microsoft Excel 2016 (< 16.0.5561.1001)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-62870

## CVE-2026-65802

External control of file name or path in Microsoft Edge for Android allows an unauthorized attacker to disclose information over a network.

Affected products:
- Microsoft Edge for Android (< 151.0.4129.59)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-65802

## CVE-2026-66310

External control of file name or path in Microsoft Edge for Android allows an unauthorized attacker to disclose information locally.

Affected products:
- Microsoft Edge for Android (< 151.0.4129.59)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-66310

## CVE-2026-66315

Use after free in Microsoft Edge (Chromium-based) allows an unauthorized attacker to execute code over a network.

Affected products:
- Microsoft Edge (Chromium-based) (< 151.0.4129.59)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-66315

## CVE-2026-66318

Origin validation error in Microsoft Edge (Chromium-based) allows an unauthorized attacker to disclose information over a network.

Affected products:
- Microsoft Edge (Chromium-based) (< 151.0.4129.59)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-66318

## Recommendation

Apply the July 2026 Microsoft security updates for the affected products:

- **Microsoft Edge:** update to version **151.0.4129.59** or later (Chromium base 151.0.7922.71/.72). See the [Edge security release notes](https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security).
- **Microsoft Office / Excel:** install the July 2026 Microsoft 365 Apps security updates. For Excel 2016, apply **KB5002886** / **KB5002877**. See the [Office security updates](https://docs.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates) page for the KB matching your Office installation.

Deploy through Windows Update, Microsoft Update Catalog, WSUS, or your patch-management channel, and verify the product versions listed above are updated.
