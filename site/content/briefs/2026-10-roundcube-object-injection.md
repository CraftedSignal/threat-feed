---
brief_id: brief-2026-10-22-roundcube-object-injection
event_id: brief-2026-10-22-roundcube-object-injection
revision: 1
activity_at: "2026-10-22T06:01:03Z"
title: 'Roundcube Webmail: Object injection in rcube_session::unserialize (CVE-2026-114724)'
slug: 2026-10-roundcube-object-injection
description: Roundcube Webmail before 1.6.20 and 1.7.x before 1.7.5 contains an object injection primitive in rcube_session::unserialize() due to improper handling of session keys prefixed with "!".
date: "2026-10-22T06:01:03Z"
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
  - Roundcube Webmail (< 1.6.20, 1.7.x < 1.7.5)
cves:
  - id: CVE-2026-114724
    cvss: 7.4
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114724
---

Roundcube Webmail before 1.6.20 and 1.7.x before 1.7.5 contains an object injection primitive in the `rcube_session::unserialize()` function. A session key prefixed with "!" was treated as having no value, resulting in the reconstructed serialized string being emitted with a key but no corresponding value. This desynchronizes the remainder of the input, causing subsequent session data to be interpreted as a serialized value. This provides an object injection primitive for an attacker able to influence stored session data. This has been addressed by upstream by rejecting such keys.
