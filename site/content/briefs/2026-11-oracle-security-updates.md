---
brief_id: brief-2026-11-oracle-security-updates
event_id: brief-2026-11-oracle-security-updates
revision: 2
activity_at: "2026-11-17T23:49:55Z"
revision_history:
  - revision: 2
    at: "2026-11-17T23:49:55Z"
    checksum: sha256:f0ffe17bfc90d25e623a1962745b96cb36163a8ca9269d947ab1177163d93166
    summary: added CVE-2026-101663
    changed_fields:
      - claim_state
      - cpes
      - cve_verification
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-101663
title: Oracle Security Updates - November 2026
slug: 2026-11-oracle-security-updates
description: Roundup of Oracle security advisories published in November 2026.
date: "2026-11-16T21:54:15Z"
lastmod: "2026-11-17T23:49:09Z"
type: threat
claim_state: <nil>
types:
  - threat
severities:
  - high
exploitation_evidence:
  status: unknown
cpes:
  - cpe:2.3:a:oracle:mobile_field_service:*:*:*:*:*:*:*:*
tags:
  - roundup
vendors:
  - Oracle
cve_verification:
  CVE-2026-101653:
    status: verified
    source: nvd
    checked_at: 2026-11-17T23:49:08.738443818Z
  CVE-2026-101663:
    status: verified
    source: nvd
    checked_at: 2026-11-17T23:49:08.956701354Z
cves:
  - id: CVE-2026-101653
    cvss: 8.8
    epss: 0.00433
    kev_status: "false"
  - id: CVE-2026-101663
    cvss: 7.4
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-101663
updates:
  - at: "2026-11-16T21:54:15Z"
    level: L1
    summary: posted roundup
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-101653
  - at: "2026-11-17T23:49:09Z"
    level: L2
    summary: added CVE-2026-101663
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-101663
---

## Overview

This roundup covers 1 Oracle security vulnerabilities. None are reported as actively exploited at the time of release.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-101653](#cve-2026-101653) | n/a |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-101653) (authoritative) |


## Recommendation

Review affected products and apply Oracle's November 2026 security updates.

## CVE-2026-101653

Oracle Mobile Field Service, a component of Oracle E-Business Suite, contains a vulnerability in its Internal Operations module. The flaw allows a low-privileged, network-adjacent attacker using HTTPS to achieve a full takeover of the application. The vulnerability carries a CVSS 3.1 base score of 8.8, indicating high impact on confidentiality, integrity, and availability.

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-101653
