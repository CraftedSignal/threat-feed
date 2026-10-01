---
title: Denial of Service Vulnerability in pypdf
slug: 2026-10-pypdf-dos
description: The pypdf library contains a vulnerability, CVE-2026-102999, that allows an attacker to cause excessive execution times by providing a crafted PDF with numerous embedded files.
date: "2026-10-01T20:22:57Z"
lastmod: "2026-10-01T20:23:04Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:py-pdf:pypdf:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - dos
  - denial-of-service
  - library-vulnerability
  - python
vendors:
  - py-pdf
products:
  - pypdf (< 6.19.0)
cves:
  - id: CVE-2026-102999
    epss: 0.00524
references:
  - https://github.com/advisories/GHSA-v247-6f48-mgcj
  - https://github.com/py-pdf/pypdf/releases/tag/6.19.0
  - https://github.com/advisories/GHSA-php9-fj8v-98fj
  - https://github.com/py-pdf/pypdf/pull/4087
action_plan:
  priority: elevated
  owners:
    - Development Team
  mitigation_plan:
    - priority: immediate
      action: Upgrade pypdf to 6.19.0
      owner: Development Team
      addresses: CVE-2026-102999
      evidence: This has been fixed in pypdf==6.19.0.
updates:
  - at: "2026-10-01T20:23:04Z"
    level: L1
    summary: added coverage for pypdf (< 6.19.0)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-php9-fj8v-98fj
---

The pypdf library is susceptible to a denial-of-service condition identified as CVE-2026-102999. This vulnerability stems from inefficient handling of embedded files within PDF documents. When an application uses the library's dictionary-based API to access embedded files, a specially crafted PDF containing a large number of these objects can trigger a performance degradation, resulting in excessively long runtimes and potential service exhaustion. This issue affects all versions of pypdf prior to 6.19.0. Organizations processing untrusted or user-supplied PDF documents using this library are at risk of resource depletion attacks targeting their document processing pipelines.

## Impact

Successful exploitation results in a denial-of-service condition where the application becomes unresponsive due to the excessive computational load required to process the malicious PDF. This impacts any system or automated service that parses, extracts, or inspects embedded content from PDF files using affected versions of pypdf.

## Recommendation

Prioritized actions for development and security teams:
- Upgrade the pypdf dependency to version 6.19.0 or later to include the fix for CVE-2026-102999.
- If upgrading is not immediately feasible, apply the patches provided in PR #4081 to mitigate the excessive runtime behavior.
- Implement resource limits, such as execution timeouts or CPU usage quotas, for processes that invoke pypdf on untrusted input files.
