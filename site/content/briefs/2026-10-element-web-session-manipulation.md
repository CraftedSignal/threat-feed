---
brief_id: brief-2026-10-30-element-web-session-manipulation
event_id: brief-2026-10-30-element-web-session-manipulation
revision: 1
activity_at: "2026-10-30T13:28:57Z"
title: 'Element Web and Element Desktop: Session manipulation via URL fragment parameters (CVE-2026-119407)'
slug: 2026-10-element-web-session-manipulation
description: Element Web and Element Desktop before 1.12.32 accept guest credentials from URL fragment parameters, which allows unauthenticated attackers to log out users and clear local stores.
date: "2026-10-30T13:28:57Z"
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
vendors:
  - Element
products:
  - Element Web (< 1.12.32)
  - Element Desktop (< 1.12.32)
cves:
  - id: CVE-2026-119407
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119407
---

Element Web and Element Desktop versions before 1.12.32 are vulnerable to session manipulation. The `loadSession` function accepts guest credentials (`guest_user_id` and `guest_access_token`) via URL fragment parameters. 

## Impact
Remote unauthenticated attackers can lure users into opening links containing these parameters to force an attacker-controlled guest session, log out the victim, and destroy unbacked end-to-end encryption keys.
