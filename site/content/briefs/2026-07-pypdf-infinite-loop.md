---
title: pypdf Vulnerability Allows Infinite Loop via Malicious PDF
slug: 2026-07-pypdf-infinite-loop
description: A vulnerability in the pypdf library allows an attacker to craft a malicious PDF that causes an infinite loop during parsing, leading to a denial-of-service condition, specifically when processing content streams containing un-terminated inline images using ASCII85 or ASCIIHex filters in pypdf versions prior to 6.14.2.
date: "2026-07-23T16:39:18Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
cpes:
  - cpe:2.3:a:pypdf_project:pypdf:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - python
  - pdf
vendors:
  - py-pdf
products:
  - pypdf (< 6.14.2)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An attacker who uses this vulnerability can craft a PDF which leads to an infinite loop.
    confidence_band: high
cves:
  - id: CVE-2026-59935
    cvss: 7.5
    epss: 0.00352
references:
  - https://github.com/advisories/GHSA-g867-7843-wf8q
  - https://github.com/py-pdf/pypdf/releases/tag/6.14.2
  - https://github.com/py-pdf/pypdf/pull/3892
---

A high-severity vulnerability, tracked as CVE-2026-59935, has been identified in the popular Python PDF library, `pypdf`. This vulnerability could allow an unauthenticated attacker to trigger an infinite loop within applications processing specially crafted PDF files, leading to a denial-of-service (DoS) condition. The issue specifically arises when `pypdf` attempts to parse content streams of a page containing an inline image with an unterminated ASCII85 or ASCIIHex filter. This scenario is particularly relevant when applications extract text from PDF pages. The vulnerability affects all versions of `pypdf` prior to 6.14.2. While no active exploitation has been confirmed, the ease of crafting such a file and the potential for disrupting services necessitates immediate action for all applications relying on vulnerable `pypdf` versions.

## Attack Chain

1. An attacker crafts a malicious PDF document.
2. The malicious PDF includes an inline image within a page's content stream.
3. The inline image is intentionally malformed, featuring an unterminated ASCII85 or ASCIIHex filter.
4. A victim's application, using a vulnerable `pypdf` library (version < 6.14.2), attempts to process the crafted PDF.
5. The application's operation, such as extracting text from the page, triggers `pypdf` to parse the malformed content stream.
6. During the parsing of the unterminated inline image data with the specified filters, `pypdf` enters an infinite loop.
7. The application becomes unresponsive, consuming excessive CPU resources and preventing further processing.
8. This continuous loop results in a denial-of-service condition for the affected application.

## Impact

Successful exploitation of CVE-2026-59935 leads to a denial-of-service condition in any application or service that utilizes the vulnerable `pypdf` library to process user-supplied PDF documents. The attack can cause the targeted application to hang indefinitely, consume all available CPU cycles, and become completely unresponsive, thereby disrupting its normal operation. This could impact critical business processes, data extraction pipelines, document management systems, or any service involving PDF parsing, potentially leading to significant operational downtime and resource exhaustion.

## Recommendation

* Upgrade `pypdf` to version 6.14.2 or later immediately to mitigate CVE-2026-59935.
* If immediate upgrade is not feasible, apply the changes from PR [#3892](https://github.com/py-pdf/pypdf/pull/3892) to address CVE-2026-59935.
