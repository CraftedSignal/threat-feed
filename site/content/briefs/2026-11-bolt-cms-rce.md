---
brief_id: brief-2026-11-01-bolt-cms-rce
event_id: brief-2026-11-01-bolt-cms-rce
revision: 1
activity_at: "2026-11-01T17:06:41Z"
title: 'Bolt CMS: Authenticated Remote Code Execution via File Manager (CVE-2022-36532)'
slug: 2026-11-bolt-cms-rce
description: A public exploit PoC has been published for CVE-2022-36532, an authenticated remote code execution vulnerability in Bolt CMS versions 5.1.12 and earlier. The vulnerability involves improper file extension enforcement and parameter confusion during file rename operations.
date: "2026-11-01T17:06:41Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: not_observed
source_assessment:
  reliability: C
  credibility: "3"
  rating: C3
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:bolt:bolt_cms:*:*:*:*:*:*:*:*
products:
  - Bolt CMS (<= 5.1.12)
cves:
  - id: CVE-2022-36532
    cvss: 8.8
    epss: 0.24314
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=36A48758-9360-5C79-B7F3-FFB060F50077
  - https://sploitus.com/exploit?id=36A48758-9360-5C79-B7F3-FFB060F50077&utm_source=rss&utm_medium=rss
---

A proof-of-concept exploit is available for CVE-2022-36532, which affects Bolt CMS versions 5.1.12 and earlier. The vulnerability allows an authenticated user with access to the file manager to achieve remote code execution. The attack involves uploading a malicious file through the asynchronous upload endpoint - where file extension restrictions are not properly enforced - and subsequently using parameter confusion during a rename operation to convert the file into an executable PHP script.
