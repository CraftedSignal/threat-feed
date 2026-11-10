---
brief_id: brief-2026-11-10-wpml-auth-bypass
event_id: brief-2026-11-10-wpml-auth-bypass
revision: 1
activity_at: "2026-11-10T08:05:14Z"
title: 'WPML Multilingual CMS: Authentication Bypass via Race Condition (CVE-2026-76877)'
slug: 2026-11-wpml-auth-bypass
description: The WPML Multilingual CMS plugin for WordPress, in versions up to and including 4.9.7, is vulnerable to an authentication bypass via a race condition in the `process_iframe_request` function's language-per-domain SSO handler.
date: "2026-11-10T08:05:14Z"
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
products:
  - WPML Multilingual CMS (<= 4.9.7)
cves:
  - id: CVE-2026-76877
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76877
---

The WPML Multilingual CMS plugin for WordPress (versions <= 4.9.7) contains a vulnerability in the `process_iframe_request` function. An authentication bypass occurs due to a race condition where the SSO handler generates a cross-domain sign-in token that is not properly bound to the user session after authentication cookies are discarded. An unauthenticated attacker can forge the `wpml_sso_token_domain` parameter and submit it to a language-domain endpoint, potentially gaining access to user accounts, including those of administrators, while the legitimate user is logging out.
