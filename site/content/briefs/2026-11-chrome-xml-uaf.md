---
brief_id: brief-2026-11-10-chrome-xml-uaf
event_id: brief-2026-11-10-chrome-xml-uaf
revision: 1
activity_at: "2026-11-10T08:36:35Z"
title: 'Google Chrome: Use-after-free in XML component (CVE-2026-125350)'
slug: 2026-11-chrome-xml-uaf
description: Google has patched a high-severity use-after-free vulnerability in the Chrome XML component that is currently being exploited in the wild.
date: "2026-11-10T08:36:35Z"
type: threat
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
cves:
  - id: CVE-2026-125350
    kev_status: unknown
references:
  - https://www.securityweek.com/chrome-update-patches-exploited-xml-zero-day-eighth-this-year/
---

Google has released security updates for Chrome to address nine vulnerabilities, including CVE-2026-125350, a high-severity use-after-free flaw in the browser's XML component. This vulnerability is confirmed to be exploited in the wild. Google has not shared additional details regarding the attacks.
