---
brief_id: brief-2026-11-08-ibm-verify-directory-session-fixation
event_id: brief-2026-11-08-ibm-verify-directory-session-fixation
revision: 1
activity_at: "2026-11-08T20:56:37Z"
title: 'IBM Security Verify Directory: Session Fixation (CVE-2026-8639)'
slug: 2026-11-ibm-verify-directory-session-fixation
description: IBM Security Verify Directory is affected by a session fixation vulnerability (CVE-2026-8639) that allows an attacker with low privileges to hijack an authenticated management console session.
date: "2026-11-08T20:56:37Z"
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
products:
  - IBM Security Verify Directory 10.0.0 through 10.0.4
  - IBM Security Verify Directory 11.0.0
cves:
  - id: CVE-2026-8639
    cvss: 8.8
    kev_status: "false"
references:
  - https://www.ibm.com/support/pages/node/7293828
  - https://sploitus.com/exploit?id=CVE-2026-8639
  - https://sploitus.com/exploit?id=CVE-2026-8639&utm_source=rss&utm_medium=rss
---

IBM Security Verify Directory 10.0.0 through 10.0.4 and 11.0.0 are vulnerable to session fixation. An attacker with low privileges can establish a session and, after the victim authenticates, hijack the authenticated session to gain unauthorized access to the directory management console. A public proof-of-concept (PoC) exploit for this vulnerability is available on Sploitus.
