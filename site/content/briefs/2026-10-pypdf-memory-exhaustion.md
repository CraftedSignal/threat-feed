---
title: pypdf Memory Exhaustion Vulnerability
slug: 2026-10-pypdf-memory-exhaustion
description: A vulnerability in the pypdf library, tracked as CVE-2026-103000, allows attackers to trigger excessive memory consumption and potential denial of service by providing crafted PDFs with large alphabetical page labels.
date: "2026-10-01T20:23:09Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:pypdf:pypdf:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - pypdf
  - memory-exhaustion
  - cve-2026-103000
products:
  - pypdf (< 6.19.0)
cves:
  - id: CVE-2026-103000
    epss: 0.00524
references:
  - https://github.com/advisories/GHSA-w23x-9jrw-r45c
  - https://github.com/py-pdf/pypdf/releases/tag/6.19.0
  - https://github.com/py-pdf/pypdf/pull/4096
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development Team
  immediate_actions:
    - action: Upgrade pypdf to 6.19.0 or later
      owner: Development Team
      due: 48h
      evidence: Fixed in pypdf==6.19.0
  mitigation_plan:
    - priority: immediate
      action: 'Apply PR #4096 patch if upgrade is delayed'
      owner: Development Team
      addresses: CVE-2026-103000
      evidence: Workaround documented in source
---

The pypdf library contains a vulnerability, identified as CVE-2026-103000, that exposes applications to a denial-of-service (DoS) condition. The issue resides in the handling of alphabetical page labels within PDF documents. When the library processes a document containing specifically crafted, excessively large alphabetical page labels, it triggers a disproportionate increase in memory usage. This can lead to service instability, resource exhaustion, or application crashes depending on the environment where the library is deployed. This vulnerability affects all versions of pypdf prior to 6.19.0. Organizations using pypdf to process untrusted or user-uploaded PDF files are at risk and should prioritize upgrading to the patched version or applying the recommended code changes.

## Impact

Successful exploitation results in a denial-of-service state for the application processing the malicious PDF. This is particularly concerning for document management systems, web scrapers, or any automated pipeline that parses user-provided PDFs. If the host environment has constrained memory, a single crafted file could induce a crash, disrupting service availability.

## Recommendation

* Upgrade the pypdf library to version 6.19.0 or later immediately to incorporate the patch for CVE-2026-103000.
* If an immediate upgrade is not possible, apply the code changes provided in the vendor pull request (PR #4096) to sanitize or limit the processing of page labels.
* Implement memory limits (e.g., cgroups, container memory limits) on processes responsible for parsing untrusted PDF files to mitigate the impact of potential resource exhaustion attacks.
