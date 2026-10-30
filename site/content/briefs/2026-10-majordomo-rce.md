---
brief_id: brief-2026-10-30-majordomo-rce
event_id: brief-2026-10-30-majordomo-rce
revision: 1
activity_at: "2026-10-30T04:30:05Z"
title: 'MajorDoMo: Unauthenticated remote code execution via update poisoning (CVE-2026-27180)'
slug: 2026-10-majordomo-rce
description: A public proof-of-concept exploit is available for CVE-2026-27180, a critical vulnerability in MajorDoMo that allows unauthenticated remote code execution via update URL poisoning.
date: "2026-10-30T04:30:05Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: not_observed
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Verified against provided source metadata
cpes:
  - cpe:2.3:a:mjdm:majordomo:-:*:*:*:*:*:*:*
products:
  - MajorDoMo (All versions)
cves:
  - id: CVE-2026-27180
    cvss: 9.8
    epss: 0.01198
    kev_status: "false"
references:
  - https://github.com/sergejey/majordomo/pull/1177
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-MBANYAMER-CVE-2026-27180-MAJORDOMO-UNAUTHENTICATED-RCE
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-MBANYAMER-CVE-2026-27180-MAJORDOMO-UNAUTHENTICATED-RCE&utm_source=rss&utm_medium=rss
---

CVE-2026-27180 is a vulnerability in MajorDoMo smart home automation software allowing unauthenticated remote code execution. The vulnerability stems from a lack of authentication and integrity checks in the 'saverestore' module, enabling an attacker to poison the update source URL, trigger a forced update, and download malicious files into the web root. A public exploit for this vulnerability has been published.
