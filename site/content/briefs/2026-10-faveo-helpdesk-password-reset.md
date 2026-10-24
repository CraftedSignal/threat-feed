---
brief_id: brief-2026-10-24-faveo-helpdesk-password-reset
event_id: brief-2026-10-24-faveo-helpdesk-password-reset
revision: 1
activity_at: "2026-10-24T20:17:47Z"
title: 'Faveo Helpdesk: Weak password recovery (CVE-2026-115973)'
slug: 2026-10-faveo-helpdesk-password-reset
description: A vulnerability in Faveo Helpdesk 2.0.3 allows for remote manipulation of password recovery functions.
date: "2026-10-24T20:17:47Z"
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
  - cpe:2.3:a:faveosuite:faveo_helpdesk_2_0_3:*:*:*:*:*:*:*:*
vendors:
  - FaveoSuite
products:
  - Faveo Helpdesk 2.0.3
cves:
  - id: CVE-2026-115973
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115973
---

A vulnerability (CVE-2026-115973) has been identified in Faveo Helpdesk 2.0.3. The issue involves the `ForgotPasswordController::sendResetLinkEmail` and `PasswordController::reset` functions within `app/Http/Controllers/Auth/ForgotPasswordController.php`. This manipulation results in weak password recovery and can be initiated remotely. The vendor was contacted early about this disclosure.
