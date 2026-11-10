---
brief_id: brief-2026-11-10-ssti-detection
event_id: brief-2026-11-10-ssti-detection
revision: 1
activity_at: "2026-11-10T02:40:50Z"
title: 'Web Server: Server Side Template Injection (SSTI) attempts'
slug: 2026-11-ssti-detection
description: Detection logic for identifying Server Side Template Injection (SSTI) attempts within web server access logs by monitoring for common template syntax in GET requests.
date: "2026-11-10T02:40:50Z"
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
references:
  - https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection
  - https://web.archive.org/web/20251112054341/https://github.com/payloadbox/ssti-payloads
  - https://github.com/SigmaHQ/sigma/blob/main/rules/web/webserver_generic/web_ssti_in_access_logs.yml
rules:
  - title: Detect Server Side Template Injection (SSTI) Attempts
    platform: sigma
    severity: high
    tactics:
      - stealth
    techniques:
      - T1221
    data_sources:
      - webserver
rules_count: 1
---

This intelligence covers patterns associated with Server Side Template Injection (SSTI) attacks. The detection focuses on identifying template expression prefixes within GET request query parameters as defined by existing Sigma detection criteria.

## False Positives
- User searches in search boxes of the respective website.
- Internal vulnerability scanners. If false positives occur, consider adding filters such as "User Agent" strings or response codes.
