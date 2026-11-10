---
brief_id: brief-2026-11-10-chrome-xml-uaf
event_id: brief-2026-11-10-chrome-xml-uaf
revision: 2
activity_at: "2026-11-10T17:01:34Z"
revision_history:
  - revision: 2
    at: "2026-11-10T17:01:34Z"
    checksum: sha256:482ca89cc5d2fc303e03ed8d1a45105c56cd350df9ccd9886117e35958dfa5ae
    summary: OS windows; OS macos; OS linux
    changed_fields:
      - affected_os
      - claim_state
      - lastmod
      - references
      - updates
    source_urls:
      - https://socprime.com/blog/cve-2026-125350-chrome-xml-zero-day-exploited-in-the-wild/
title: 'Google Chrome: Use-after-free in XML component (CVE-2026-125350)'
slug: 2026-11-chrome-xml-uaf
description: Google has patched a high-severity use-after-free vulnerability in the Chrome XML component that is currently being exploited in the wild.
date: "2026-11-10T08:36:35Z"
lastmod: "2026-11-10T17:00:34Z"
type: threat
claim_state: <nil>
types:
  - threat
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.securityweek.com/chrome-update-patches-exploited-xml-zero-day-eighth-this-year/
  observed_at: "2026-11-10T00:00:00Z"
  confidence: high
source_assessment:
  reliability: C
  credibility: "2"
  rating: C2
  likelihood: likely
vendors:
  - Google
products:
  - Chrome
affected_os:
  - Windows
  - macOS
  - Linux
cves:
  - id: CVE-2026-125350
    kev_status: unknown
references:
  - https://www.securityweek.com/chrome-update-patches-exploited-xml-zero-day-eighth-this-year/
  - https://socprime.com/blog/cve-2026-125350-chrome-xml-zero-day-exploited-in-the-wild/
updates:
  - at: "2026-11-10T17:00:34Z"
    level: L1
    summary: OS windows; OS macos; OS linux
    sources:
      - socprime
    source_urls:
      - https://socprime.com/blog/cve-2026-125350-chrome-xml-zero-day-exploited-in-the-wild/
---

Google has released security updates for Chrome to address nine vulnerabilities, including CVE-2026-125350, a high-severity use-after-free flaw in the browser's XML component. This vulnerability is confirmed to be exploited in the wild. Google has not shared additional details regarding the attacks.
