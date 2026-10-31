---
brief_id: brief-2026-10-31-webdyne-perl-vulnerabilities
event_id: brief-2026-10-31-webdyne-perl-vulnerabilities
revision: 1
activity_at: "2026-10-31T19:51:40Z"
title: 'WebDyne for Perl: Multiple Vulnerabilities (CVE-2026-78188, CVE-2026-78189, CVE-2026-78190)'
slug: 2026-10-webdyne-perl-vulnerabilities
description: WebDyne for Perl is affected by multiple vulnerabilities involving session cookie attributes, path traversal, and unescaped request parameters.
date: "2026-10-31T19:51:40Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: D
  credibility: "3"
  rating: D3
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:webdyne:for_perl:*:*:*:*:*:*:*:*
vendors:
  - WebDyne
products:
  - WebDyne for Perl (2.014-3.021)
cves:
  - id: CVE-2026-78188
    kev_status: "false"
  - id: CVE-2026-78189
    kev_status: "false"
  - id: CVE-2026-78190
    kev_status: "false"
references:
  - Robert Rothenberg, Oct 31
  - https://seclists.org/oss-sec/2026/q4/458
---

Robert Rothenberg reported three vulnerabilities in WebDyne for Perl:
- CVE-2026-78188: Versions 2.014 through 3.021 issue session cookies without Secure, HttpOnly, and SameSite attributes.
- CVE-2026-78189: Versions 3.007 through 3.021 allow the execution of .psp files outside the document root via path traversal in the PSGI API route fallback.
- CVE-2026-78190: Versions 2.014 through 3.021 reflect request parameters unescaped into form fields.
