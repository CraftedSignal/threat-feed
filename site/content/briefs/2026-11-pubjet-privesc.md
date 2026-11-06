---
brief_id: brief-2026-11-06-pubjet-privesc
event_id: brief-2026-11-06-pubjet-privesc
revision: 1
activity_at: "2026-11-06T15:19:42Z"
title: 'Pubjet WordPress Plugin: Privilege Escalation (CVE-2026-103479)'
slug: 2026-11-pubjet-privesc
description: The Pubjet WordPress plugin contains a vulnerability in the `checkToken()` AJAX handler that allows authenticated users with Subscriber-level access or higher to escalate privileges by overwriting stored REST API credentials.
date: "2026-11-06T15:19:42Z"
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
  - Pubjet (<= 5.4.8)
cves:
  - id: CVE-2026-103479
    cvss: 7.6
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103479
---

The Pubjet WordPress plugin (versions 5.4.8 and earlier) is vulnerable to privilege escalation. The `checkToken()` AJAX handler, registered as `wp_ajax_pubjet-check-token`, lacks capability checks and nonce verification. This allows authenticated attackers with Subscriber-level access to overwrite the plugin's stored REST API credential. By planting an attacker-chosen token, the attacker can authenticate as an authorized Pubjet API client to access restricted endpoints, including `createReportage`, `updateReportage`, `deleteReportage`, `toggleCopyright`, and `createBacklink`.
