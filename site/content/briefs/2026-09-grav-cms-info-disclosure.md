---
title: Unauthenticated Information Disclosure in Grav CMS Clockwork Profiler
slug: 2026-09-grav-cms-info-disclosure
description: Grav CMS versions 1.7.0-1.7.53.2 and 2.0.0-2.0.21 suffer from an unauthenticated information disclosure vulnerability in the Clockwork profiler endpoint when the debugger is enabled.
date: "2026-09-17T13:57:18Z"
type: advisory
types:
  - advisory
severities:
  - high
cves:
  - id: CVE-2026-92916
    cvss: 7.5
---

Grav CMS versions 1.7.0 through 1.7.53.2 and 2.0.0 through 2.0.21 contain a critical information disclosure vulnerability within the Clockwork profiler endpoint (CVE-2026-92916). When the
