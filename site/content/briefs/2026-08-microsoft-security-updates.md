---
title: Microsoft Security Updates — August 2026
slug: 2026-08-microsoft-security-updates
description: Roundup of Microsoft security advisories published in August 2026.
date: "2026-08-01T01:41:40Z"
lastmod: "2026-08-04T14:11:28Z"
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

Aggregated Microsoft security advisories for August 2026.

## Summary

This roundup tracks five Microsoft CVEs published in the August 2026 cycle:

- **CVE-2026-62870** (CVSS 8.8) — Microsoft Excel Remote Code Execution Vulnerability.
- **CVE-2026-65802** (CVSS 7.4) — Microsoft Edge for Android Information Disclosure Vulnerability.
- **CVE-2026-66310** (CVSS 7.7) — Microsoft Edge for Android Information Disclosure Vulnerability.
- **CVE-2026-66315** (CVSS 7.5) — Microsoft Edge (Chromium-based) Remote Code Execution Vulnerability.
- **CVE-2026-66318** (CVSS 8.1) — Microsoft Edge (Chromium-based) Information Disclosure Vulnerability.

## Recommendation

Apply the following patches:

- **Microsoft Edge:** update to version **151.0.4129.59** or later. See the [Edge security release notes](https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security).
- **Microsoft Office / Excel:** install the July 2026 Microsoft 365 Apps security updates. For Excel 2016, apply **KB5002886** / **KB5002877**. See the [Office security updates](https://docs.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates) page for the relevant KB for your installation.

Verify the affected product versions listed above and deploy the corresponding updates through Windows Update, Microsoft Update Catalog, or your patch-management channel.
