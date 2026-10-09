---
title: Microsoft Security Updates - October 2026
slug: 2026-10-microsoft-security-updates
description: Roundup of Microsoft security advisories published in October 2026.
date: "2026-10-02T20:23:41Z"
lastmod: "2026-10-09T00:03:59Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - roundup
vendors:
  - Microsoft
cves:
  - id: CVE-2026-96940
    product: Exchange Server
    cvss: 8.8
    epss: 0.00496
  - id: CVE-2026-69435
    cvss: 9.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-69435
updates:
  - at: "2026-10-02T20:23:41Z"
    level: L1
    summary: posted roundup
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-96940
  - at: "2026-10-09T00:03:59Z"
    level: L2
    summary: added CVE-2026-69435
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-69435
---

This roundup covers 1 Microsoft security vulnerabilities. None are reported as actively exploited at the time of release. The issues affect Exchange Server.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-96940](#cve-2026-96940) | Exchange Server |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-96940) (authoritative) |


## CVE-2026-96940

Microsoft Exchange Server contains a vulnerability due to weak authorization that allows an authenticated attacker to elevate their privileges over the network.

Affected products:
- Exchange Server

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-96940
