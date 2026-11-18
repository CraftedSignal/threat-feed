---
brief_id: brief-2026-11-18-io-socket-ssl-vulnerabilities
event_id: brief-2026-11-18-io-socket-ssl-vulnerabilities
revision: 1
activity_at: "2026-11-18T01:52:56Z"
title: 'IO-Socket-SSL: Multiple vulnerabilities in PublicSuffix module (CVE-2026-129891, CVE-2026-129892)'
slug: 2026-11-io-socket-ssl-vulnerabilities
description: The Perl module IO::Socket::SSL::PublicSuffix (versions through 2.099) is vulnerable to public suffix list manipulation (CVE-2026-129891) and arbitrary code injection (CVE-2026-129892) during the execution of the update_self_from_url function.
date: "2026-11-18T01:52:56Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: D
  credibility: "3"
  rating: D3
  likelihood: roughly even chance
products:
  - IO::Socket::SSL::PublicSuffix
product_versions:
  - product: IO::Socket::SSL::PublicSuffix
    range: <= 2.099
affected_os:
  - Perl
cves:
  - id: CVE-2026-129891
    kev_status: "false"
  - id: CVE-2026-129892
    kev_status: "false"
references:
  - https://seclists.org/oss-sec/2026/q4/759
  - https://cveawg.mitre.org/api/cve/CVE-2026-129891
  - https://cveawg.mitre.org/api/cve/CVE-2026-129892
---

## Overview
IO::Socket::SSL::PublicSuffix versions through 2.099 for Perl contain two vulnerabilities involving the `update_self_from_url` function, which is used to update the module's public suffix list.

## Attack Chain
### CVE-2026-129891 (MitM Suffix Manipulation)
The `update_self_from_url` function fetches the public suffix list over cleartext HTTP without integrity checks. An on-path attacker can supply a malicious list, causing the module to misidentify public suffix boundaries, which may lead to the acceptance of fraudulent wildcard certificates for public suffixes.

### CVE-2026-129892 (Code Injection)
The `update_self_from_url` function rewrites the module's source file by appending lines from a fetched list into a heredoc block. The module fails to validate that the fetched content contains only domain data. An attacker can inject a line containing `END_BUILTIN_DATA` to terminate the data block prematurely, causing subsequent lines in the fetched content to be executed as arbitrary Perl code. This code executes in any process that loads the `IO::Socket::SSL` module until the module file is reinstalled. Execution requires that the updater runs with write access to the installed module.

## Impact
Successful exploitation allows an attacker to manipulate hostname validation (CVE-2026-129891) or execute arbitrary Perl code (CVE-2026-129892) within any process that loads the module.

## Recommendation
- Upgrade to a future IO-Socket-SSL release or apply the upstream patch.
- For CVE-2026-129891: Until a fix is applied, pass an explicit https URL to `update_self_from_url` instead of calling it with no arguments.
- For CVE-2026-129892: Until a fix is applied, do not run `update_self_from_url`.
