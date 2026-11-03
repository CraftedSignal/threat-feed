---
brief_id: brief-2026-11-03-surecart-account-takeover
event_id: brief-2026-11-03-surecart-account-takeover
revision: 1
activity_at: "2026-11-03T05:54:57Z"
title: 'SureCart: Unauthenticated account takeover vulnerability (CVE-2026-120574)'
slug: 2026-11-surecart-account-takeover
description: The SureCart WordPress plugin contains an authentication vulnerability in the VerificationCodeController REST endpoint, allowing unauthenticated attackers to brute-force verification codes to hijack user accounts.
date: "2026-11-03T05:54:57Z"
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
  - cpe:2.3:a:surecart:surecart:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - vulnerability
  - authentication
vendors:
  - SureCart
products:
  - SureCart (<= 4.9.5)
cves:
  - id: CVE-2026-120574
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120574
---

The SureCart plugin for WordPress is vulnerable to unauthenticated account takeover in all versions up to, and including, 4.9.5. The passwordless one-time-code login REST route (VerificationCodeController::verify()) resolves an attacker-supplied login to any WordPress user, verifies a 6-digit code, and calls wp_set_auth_cookie() for that user. This path lacks per-account attempt counters, persistent email/IP lockout, or rate limits. An unauthenticated attacker can trigger a code for any user via a companion endpoint and brute-force the 6-digit code to obtain an authenticated session as that user, resulting in a full administrator account takeover.
