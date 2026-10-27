---
brief_id: brief-2026-10-27-eaton-easye4-static-nonce
event_id: brief-2026-10-27-eaton-easye4-static-nonce
revision: 2
activity_at: "2026-10-27T22:07:56Z"
revision_history:
  - revision: 2
    at: "2026-10-27T22:07:56Z"
    checksum: sha256:76b11c6adc340a40d04e3069a82e070b71388eba419a9a4c5a1748f0061f7073
    summary: severity → high; added CVE-2026-41021
    changed_fields:
      - cves
      - lastmod
      - references
      - severity
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-41021
title: 'Eaton easyE4: Authentication replay vulnerability via static nonce (CVE-2026-41020)'
slug: 2026-10-eaton-easye4-static-nonce
description: Eaton easyE4 uses a static nonce during authentication, allowing an unauthenticated attacker to replay captured authentication traffic to gain unauthorized access to the device.
date: "2026-10-27T13:50:05Z"
lastmod: "2026-10-27T22:06:51Z"
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
  - cpe:2.3:a:eaton:easye4:*:*:*:*:*:*:*:*
vendors:
  - Eaton
products:
  - easyE4
cves:
  - id: CVE-2026-41020
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-41021
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41020
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41021
updates:
  - at: "2026-10-27T22:06:51Z"
    level: L2
    summary: severity → high; added CVE-2026-41021
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-41021
---

Eaton easyE4 devices utilize a static nonce during authentication. This allows an unauthenticated attacker with access to captured authentication traffic to replay a valid authentication exchange and gain unauthorized access to the device.
