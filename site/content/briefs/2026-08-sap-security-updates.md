---
title: SAP Security Updates - August 2026
slug: 2026-08-sap-security-updates
description: Roundup of SAP security advisories published in August 2026.
date: "2026-08-11T01:36:23Z"
lastmod: "2026-08-11T01:37:58Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - roundup
vendors:
  - SAP
products:
  - Manufacturing Integration and Intelligence (MII)
  - Manufacturing Integration and Intelligence
  - Approuter
  - ABAP Development Tools
  - NetWeaver AS ABAP
  - SAP BusinessObjects Business Intelligence Platform
cves:
  - id: CVE-2026-34265
    cvss: 9.8
  - id: CVE-2026-44758
    cvss: 9.1
  - id: CVE-2026-44763
    cvss: 7.6
  - id: CVE-2026-44764
    cvss: 7.3
  - id: CVE-2026-44765
    cvss: 7.3
  - id: CVE-2026-58230
    cvss: 7
  - id: CVE-2026-58243
    cvss: 8.8
  - id: CVE-2026-66763
    cvss: 7.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-44758
  - https://nvd.nist.gov/vuln/detail/CVE-2026-44763
  - https://nvd.nist.gov/vuln/detail/CVE-2026-44764
  - https://nvd.nist.gov/vuln/detail/CVE-2026-44765
  - https://nvd.nist.gov/vuln/detail/CVE-2026-58230
  - https://nvd.nist.gov/vuln/detail/CVE-2026-58243
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66763
updates:
  - at: "2026-08-11T01:37:06Z"
    level: L2
    summary: added CVE-2026-44764 +4
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-44764
      - https://nvd.nist.gov/vuln/detail/CVE-2026-44765
      - https://nvd.nist.gov/vuln/detail/CVE-2026-58230
      - https://nvd.nist.gov/vuln/detail/CVE-2026-58243
      - https://nvd.nist.gov/vuln/detail/CVE-2026-66763
---

This roundup covers 7 SAP security vulnerabilities. CVSS base scores range from 7.0 to 9.8. None are reported as actively exploited at the time of release. The issues affect ABAP Development Tools, Approuter, Manufacturing Integration and Intelligence, NetWeaver Application Server ABAP.

## Summary

| CVE | CVSS | Product | Summary |
|-----|------|---------|---------|
| CVE-2026-34265 | 9.8 | NetWeaver Application Server ABAP | CVE-2026-34265 is a critical vulnerability in the SAP NetWeaver Application Server ABAP DIAG protocol parsing logic. An unauthenticated attacker can exploit this flaw to cause memory corruption, potentially leading to unauthorized disclosure of sensitive system information or a denial-of-service condition affecting system availability. |
| CVE-2026-44758 | 9.1 | Manufacturing Integration and Intelligence (MII) | SAP Manufacturing Integration and Intelligence (MII) is susceptible to a command injection vulnerability due to insufficient input validation. An attacker with high-level privileges can supply crafted input that results in arbitrary operating system command execution, potentially compromising the confidentiality, integrity, and availability of the affected system. |
| CVE-2026-44763 | 7.6 | Manufacturing Integration and Intelligence | SAP Manufacturing Integration and Intelligence is susceptible to a path traversal vulnerability due to insufficient validation of file paths in certain functions. A privileged attacker can use specially crafted input to write files to arbitrary locations on the host system. Successful exploitation requires a secondary interaction by a legitimate user and compromises the confidentiality, integrity, and availability of the affected system. |
| CVE-2026-44764 | 7.3 | Manufacturing Integration and Intelligence | SAP Manufacturing Integration and Intelligence is vulnerable to a missing authorization check in the Cost Servlet, allowing an unauthenticated attacker to manipulate business data. By sending crafted requests with specific parameter values, an attacker can perform unauthorized read, create, modify, or delete operations, impacting the overall system confidentiality, integrity, and availability. |
| CVE-2026-44765 | 7.3 | Manufacturing Integration and Intelligence | SAP Manufacturing Integration and Intelligence contains a missing authorization check vulnerability allowing unauthenticated remote attackers to interact with scheduling functions. Exploitation allows for the unauthorized retrieval, creation, modification, or deletion of application-managed scheduling data. |
| CVE-2026-58230 | 7.0 | Approuter | SAP Approuter contains a vulnerability where insufficient validation of token content under specific, non-default configurations allows an unauthenticated attacker to redirect sensitive credential material to an attacker-controlled destination. While exploitation requires high complexity due to prerequisite environmental conditions, successful execution leads to a high impact on confidentiality. |
| CVE-2026-58243 | 8.8 | ABAP Development Tools | SAP ABAP Development Tools fails to perform adequate authorization checks, enabling low-privileged users to execute unauthorized database operations against SAP NetWeaver AS ABAP. This vulnerability allows an attacker to read or modify sensitive application data and disrupt service availability, posing a high risk to confidentiality, integrity, and availability. |


## CVE-2026-34265

CVE-2026-34265 is a critical vulnerability in the SAP NetWeaver Application Server ABAP DIAG protocol parsing logic. An unauthenticated attacker can exploit this flaw to cause memory corruption, potentially leading to unauthorized disclosure of sensitive system information or a denial-of-service condition affecting system availability.

Affected products:
- NetWeaver Application Server ABAP

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-34265

## CVE-2026-44758

SAP Manufacturing Integration and Intelligence (MII) is susceptible to a command injection vulnerability due to insufficient input validation. An attacker with high-level privileges can supply crafted input that results in arbitrary operating system command execution, potentially compromising the confidentiality, integrity, and availability of the affected system.

Affected products:
- Manufacturing Integration and Intelligence (MII)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-44758

## CVE-2026-44763

SAP Manufacturing Integration and Intelligence is susceptible to a path traversal vulnerability due to insufficient validation of file paths in certain functions. A privileged attacker can use specially crafted input to write files to arbitrary locations on the host system. Successful exploitation requires a secondary interaction by a legitimate user and compromises the confidentiality, integrity, and availability of the affected system.

Affected products:
- Manufacturing Integration and Intelligence

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-44763

## CVE-2026-44764

SAP Manufacturing Integration and Intelligence is vulnerable to a missing authorization check in the Cost Servlet, allowing an unauthenticated attacker to manipulate business data. By sending crafted requests with specific parameter values, an attacker can perform unauthorized read, create, modify, or delete operations, impacting the overall system confidentiality, integrity, and availability.

Affected products:
- Manufacturing Integration and Intelligence

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-44764

## CVE-2026-44765

SAP Manufacturing Integration and Intelligence contains a missing authorization check vulnerability allowing unauthenticated remote attackers to interact with scheduling functions. Exploitation allows for the unauthorized retrieval, creation, modification, or deletion of application-managed scheduling data.

Affected products:
- Manufacturing Integration and Intelligence

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-44765

## CVE-2026-58230

SAP Approuter contains a vulnerability where insufficient validation of token content under specific, non-default configurations allows an unauthenticated attacker to redirect sensitive credential material to an attacker-controlled destination. While exploitation requires high complexity due to prerequisite environmental conditions, successful execution leads to a high impact on confidentiality.

Affected products:
- Approuter

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-58230

## CVE-2026-58243

SAP ABAP Development Tools fails to perform adequate authorization checks, enabling low-privileged users to execute unauthorized database operations against SAP NetWeaver AS ABAP. This vulnerability allows an attacker to read or modify sensitive application data and disrupt service availability, posing a high risk to confidentiality, integrity, and availability.

Affected products:
- ABAP Development Tools
- NetWeaver AS ABAP

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-58243
