---
brief_id: brief-2026-10-22-tastyigniter-php-injection
event_id: brief-2026-10-22-tastyigniter-php-injection
revision: 1
activity_at: "2026-10-22T03:52:08Z"
title: 'TastyIgniter: PHP object injection vulnerability (CVE-2026-29001)'
slug: 2026-10-tastyigniter-php-injection
description: TastyIgniter through 4.4.5 contains a PHP object injection vulnerability that allows authenticated administrators to achieve arbitrary operating-system command execution.
date: "2026-10-22T03:52:08Z"
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
  - cpe:2.3:a:tastyigniter:tastyigniter:*:*:*:*:*:*:*:*
vendors:
  - TastyIgniter
products:
  - TastyIgniter (through 4.4.5)
cves:
  - id: CVE-2026-29001
    cvss: 7.2
    kev_status: "false"
references:
  - CVE-2026-29001
  - https://nvd.nist.gov/vuln/detail/CVE-2026-29001
---

TastyIgniter through 4.4.5 contains a PHP object injection vulnerability. Authenticated administrators can submit a serialized PHP object as a settings value, which is stored unsanitized and later unserialized by `getValueAttribute()` when the setting is read. This allows for the submission of a serialized gadget chain to achieve arbitrary operating-system command execution as the PHP application process user. The impact persists until the setting value is overwritten.
