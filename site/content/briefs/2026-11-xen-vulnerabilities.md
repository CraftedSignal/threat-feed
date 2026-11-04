---
brief_id: brief-2026-11-03-xen-vulnerabilities
event_id: brief-2026-11-03-xen-vulnerabilities
revision: 2
activity_at: "2026-11-04T15:03:07Z"
revision_history:
  - revision: 2
    at: "2026-11-04T15:03:07Z"
    checksum: sha256:b0fb4a45d481648e5ff64f78260c7891ddddf6630e58109142a563e6c1b6cf86
    summary: new vendor
    changed_fields:
      - affected_vendors
      - claim_state
      - lastmod
      - references
      - updates
    source_urls:
      - https://pwn.watch/i/xen-xsa-523-grant-copy-guest-escape-cve-2026-102703
title: Multiple vulnerabilities in Xen
slug: 2026-11-xen-vulnerabilities
description: Multiple vulnerabilities have been discovered in Xen that allow an attacker to cause a breach of data confidentiality and data integrity.
date: "2026-11-03T15:46:13Z"
lastmod: "2026-11-04T15:02:32Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
vendors:
  - Xen Project
  - Vates
  - Qubes OS
  - Debian
cves:
  - id: CVE-2026-102703
    kev_status: unknown
  - id: CVE-2026-102704
    kev_status: unknown
references:
  - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1447/
  - https://xenbits.xen.org/xsa/advisory-523.html
  - https://www.cve.org/CVERecord?id=CVE-2026-102703
  - https://www.cve.org/CVERecord?id=CVE-2026-102704
  - https://pwn.watch/i/xen-xsa-523-grant-copy-guest-escape-cve-2026-102703
updates:
  - at: "2026-11-04T15:02:32Z"
    level: L1
    summary: new vendor
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/xen-xsa-523-grant-copy-guest-escape-cve-2026-102703
---
