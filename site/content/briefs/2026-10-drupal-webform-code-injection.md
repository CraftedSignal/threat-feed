---
brief_id: brief-2026-10-22-drupal-webform-code-injection
event_id: brief-2026-10-22-drupal-webform-code-injection
revision: 1
activity_at: "2026-10-22T16:14:42Z"
title: 'Drupal Webform: Code injection via template engine (CVE-2026-96355)'
slug: 2026-10-drupal-webform-code-injection
description: The Drupal Webform module is affected by an Improper Neutralization of Special Elements Used in a Template Engine vulnerability, which allows for Code Injection.
date: "2026-10-22T16:14:42Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
products:
  - Webform (0.0.0-6.2.12, 6.3.0-6.3.1)
cves:
  - id: CVE-2026-96355
    cvss: 9.1
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96355
---

Drupal Webform is affected by a vulnerability identified as CVE-2026-96355. This issue involves the improper neutralization of special elements within the module's template engine, resulting in Code Injection. This vulnerability affects Webform versions from 0.0.0 to 6.2.12 and from 6.3.0 to 6.3.1.
