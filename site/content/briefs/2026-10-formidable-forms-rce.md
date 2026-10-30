---
brief_id: brief-2026-10-30-formidable-forms-rce
event_id: brief-2026-10-30-formidable-forms-rce
revision: 1
activity_at: "2026-10-30T13:28:26Z"
title: 'Formidable Forms: Arbitrary Plugin Installation (CVE-2026-89435)'
slug: 2026-10-formidable-forms-rce
description: The Formidable Forms WordPress plugin is vulnerable to arbitrary plugin installation via the 'file_url' parameter in versions up to and including 6.35.
date: "2026-10-30T13:28:26Z"
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
  - cpe:2.3:a:formidable_forms:formidable_forms:*:*:*:*:*:*:*:*
tags:
  - wordpress
  - vulnerability
vendors:
  - Formidable Forms
products:
  - Formidable Forms (<= 6.35)
cves:
  - id: CVE-2026-89435
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-89435
---

The Formidable Forms plugin for WordPress (all versions up to and including 6.35) is vulnerable to arbitrary plugin installation. The issue arises from insufficient URL prefix validation in the 'validate_url_is_in_s3_bucket()' function and a permission callback that relies on a shared token accessible to users with the 'frm_view_forms' capability, without checking for 'install_plugins' or 'activate_plugins' privileges. The vulnerability is exploitable by authenticated users with subscriber-level access and above, provided the site is using the free version of the plugin (Formidable Pro is not installed).
