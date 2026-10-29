---
brief_id: brief-2026-10-29-basercms-path-traversal
event_id: brief-2026-10-29-basercms-path-traversal
revision: 1
activity_at: "2026-10-29T19:57:53Z"
title: 'baserCMS: BcThemeFile plugin arbitrary file write (CVE-2026-114622)'
slug: 2026-10-basercms-path-traversal
description: A path traversal vulnerability exists in the BcThemeFile plugin for baserCMS where percent-encoded traversal sequences bypass validation, allowing an authenticated administrator to write PHP files outside the intended theme directory.
date: "2026-10-29T19:57:53Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:basercms:basercms:*:*:*:*:*:*:*:*
vendors:
  - baserCMS
products:
  - BcThemeFile plugin (5.2.3 before 5.3.2, 5.4.0 before 5.4.2)
cves:
  - id: CVE-2026-114622
    kev_status: unknown
  - id: CVE-2026-30940
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114622
---

CVE-2026-114622 affects the optional BcThemeFile plugin in baserCMS versions 5.2.3 before 5.3.2 and 5.4.0 before 5.4.2. The Admin API performs validation before applying `rawurldecode()` to path inputs. Because `normalizePath()` only resolves literal dot segments, percent-encoded traversal sequences can bypass containment checks. An authenticated administrator can exploit this to write PHP files into writable locations, such as the webroot, exceeding the intended theme-template editing boundary. This issue is a bypass of protections associated with CVE-2026-30940.
